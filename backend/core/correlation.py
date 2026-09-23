"""
Apex-SOC Stateful Sliding-Window Correlation Engine

Architecture:
  - Per-entity (source IP) state tracking inside a 5-minute sliding window.
  - Attack chain detection: Failed Login(s) → Successful Login → Sudo → Incident.
  - Risk Score formula:
      risk = (severity_weight × 40) + (frequency_score × 30) + (asset_weight × 30)
      clamped to [0, 100].

MITRE Mapping of promoted incident: T1110 → T1078 → T1548.003
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Deque, Dict, List, Optional

from models.schemas import Alert, Incident, LogEvent, Severity


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

WINDOW_SECONDS: int = 300          # 5-minute sliding window
FAILED_LOGIN_THRESHOLD: int = 10   # Failed logins to start tracking
CLEANUP_INTERVAL: int = 60         # Seconds between state GC runs


# ---------------------------------------------------------------------------
# Severity → numeric weight mapping
# ---------------------------------------------------------------------------

SEVERITY_WEIGHTS: Dict[str, float] = {
    "INFO":     0.0,
    "LOW":      0.25,
    "MEDIUM":   0.50,
    "HIGH":     0.75,
    "CRITICAL": 1.0,
}

# Asset sensitivity tiers (hostname or IP prefix → weight)
ASSET_TIERS: Dict[str, float] = {
    "prod":     1.0,
    "db":       1.0,
    "database": 1.0,
    "web":      0.75,
    "api":      0.75,
    "dev":      0.25,
    "test":     0.10,
}

DEFAULT_ASSET_WEIGHT: float = 0.50


# ---------------------------------------------------------------------------
# Entity State
# ---------------------------------------------------------------------------

@dataclass
class EntityState:
    """Tracks per-IP activity inside the sliding window."""

    source_ip: str
    events: Deque[LogEvent] = field(default_factory=deque)
    alerts: Deque[Alert] = field(default_factory=deque)

    # Attack chain flags (True once observed inside window)
    has_failed_logins: bool = False
    has_successful_login: bool = False
    has_privilege_escalation: bool = False
    incident_promoted: bool = False

    # Aggregated counters
    failed_login_count: int = 0
    total_event_count: int = 0

    # Mutable risk score
    current_risk_score: float = 0.0

    def add_event(self, event: LogEvent) -> None:
        self.events.append(event)
        self.total_event_count += 1

    def add_alert(self, alert: Alert) -> None:
        self.alerts.append(alert)

    def purge_expired(self, window_seconds: int = WINDOW_SECONDS) -> None:
        """Remove events/alerts older than the sliding window."""
        cutoff = time.time() - window_seconds
        while self.events:
            ts = self.events[0].timestamp
            if isinstance(ts, datetime):
                epoch = ts.replace(tzinfo=timezone.utc).timestamp() \
                    if ts.tzinfo is None else ts.timestamp()
            else:
                epoch = float(ts)
            if epoch < cutoff:
                self.events.popleft()
            else:
                break

        while self.alerts:
            ts = self.alerts[0].triggered_at
            epoch = ts.replace(tzinfo=timezone.utc).timestamp() \
                if ts.tzinfo is None else ts.timestamp()
            if epoch < cutoff:
                self.alerts.popleft()
            else:
                break

        # Recount after purge — use alert techniques (T1110) for reliability
        self.failed_login_count = sum(
            1 for a in self.alerts
            if a.mitre_technique == "T1110" or "failed" in a.rule_name.lower()
        )


# ---------------------------------------------------------------------------
# Risk Score Calculator
# ---------------------------------------------------------------------------

class RiskCalculator:
    """
    Implements the Apex-SOC risk scoring formula.

    risk = (severity_weight × 40) + (frequency_score × 30) + (asset_weight × 30)

    Where:
      severity_weight  = normalised max severity in the alert chain [0, 1]
      frequency_score  = min(failed_login_count / 50, 1)  [0, 1]  (saturates at 50)
      asset_weight     = sensitivity of the targeted asset [0, 1]
    """

    @staticmethod
    def compute(
        state: EntityState,
        max_severity: Severity = Severity.HIGH,
        asset_hostname: Optional[str] = None,
    ) -> float:
        # --- Severity component ---
        sev_weight = SEVERITY_WEIGHTS.get(max_severity.value, 0.5)

        # --- Frequency component ---
        freq_score = min(state.failed_login_count / 50.0, 1.0)

        # --- Asset component ---
        asset_weight = DEFAULT_ASSET_WEIGHT
        if asset_hostname:
            hostname_lower = asset_hostname.lower()
            for tier_key, tier_weight in ASSET_TIERS.items():
                if tier_key in hostname_lower:
                    asset_weight = tier_weight
                    break

        # --- Composite ---
        risk = (sev_weight * 40.0) + (freq_score * 30.0) + (asset_weight * 30.0)
        return round(min(max(risk, 0.0), 100.0), 2)


# ---------------------------------------------------------------------------
# Correlation Engine
# ---------------------------------------------------------------------------

class CorrelationEngine:
    """
    Stateful, thread-safe sliding-window correlation engine.

    Processing pipeline per ingested alert:
      1. Purge expired events from entity state.
      2. Classify the alert type (failed login / success / sudo).
      3. Update entity state flags and counters.
      4. Evaluate promotion conditions.
      5. If conditions met → promote to HIGH SEVERITY Incident.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entity_states: Dict[str, EntityState] = {}
        self._incidents: List[Incident] = []
        self._all_events: Deque[LogEvent] = deque(maxlen=10_000)
        self._all_alerts: Deque[Alert] = deque(maxlen=5_000)
        self._risk_calculator = RiskCalculator()

        # Start background GC thread
        self._gc_thread = threading.Thread(
            target=self._gc_loop, daemon=True, name="correlation-gc"
        )
        self._gc_thread.start()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def process_alerts(
        self, event: LogEvent, alerts: List[Alert]
    ) -> Optional[Incident]:
        """
        Main entry point.  Accepts a normalised event and its detection alerts.
        Returns a promoted Incident if the chain threshold is crossed, else None.
        """
        with self._lock:
            self._all_events.append(event)
            for alert in alerts:
                self._all_alerts.append(alert)

            if not event.source_ip:
                return None  # Cannot correlate without a source IP

            state = self._get_or_create_state(event.source_ip)
            state.purge_expired()
            state.add_event(event)
            for alert in alerts:
                state.add_alert(alert)

            # --- Classify alert types ---
            for alert in alerts:
                technique = alert.mitre_technique
                rule_name = alert.rule_name.lower()

                if technique == "T1110" or "failed" in rule_name:
                    state.failed_login_count += 1
                    if state.failed_login_count >= FAILED_LOGIN_THRESHOLD:
                        state.has_failed_logins = True

                elif technique in ("T1078",) or "successful" in rule_name:
                    state.has_successful_login = True

                elif technique in ("T1548", "T1548.003") or "sudo" in rule_name:
                    state.has_privilege_escalation = True

            # --- Update live risk score ---
            if state.failed_login_count > 0:
                max_sev = self._max_severity(alerts)
                state.current_risk_score = self._risk_calculator.compute(
                    state,
                    max_severity=max_sev,
                    asset_hostname=event.hostname,
                )

            # --- Check promotion conditions ---
            incident = self._try_promote(state, event)
            return incident

    def get_incidents(self) -> List[Incident]:
        with self._lock:
            return list(self._incidents)

    def get_stats(self) -> Dict:
        with self._lock:
            now = time.time()
            one_hour_ago = now - 3600
            events_last_hour = sum(
                1 for e in self._all_events
                if self._event_epoch(e) >= one_hour_ago
            )
            critical_alerts = sum(
                1 for a in self._all_alerts
                if a.severity == Severity.CRITICAL
            )
            high_alerts = sum(
                1 for a in self._all_alerts
                if a.severity == Severity.HIGH
            )
            return {
                "total_events": len(self._all_events),
                "total_incidents": len(self._incidents),
                "critical_alerts": critical_alerts,
                "high_alerts": high_alerts,
                "events_last_hour": events_last_hour,
            }

    def get_top_ips(self, limit: int = 10) -> List[Dict]:
        with self._lock:
            results = []
            for ip, state in self._entity_states.items():
                results.append({
                    "ip": ip,
                    "event_count": state.total_event_count,
                    "failed_logins": state.failed_login_count,
                    "risk_score": state.current_risk_score,
                    "is_flagged": state.incident_promoted
                    or state.current_risk_score >= 60.0,
                })
            results.sort(key=lambda x: x["risk_score"], reverse=True)
            return results[:limit]

    def get_recent_events(self, limit: int = 100) -> List[LogEvent]:
        with self._lock:
            events = list(self._all_events)
            events.sort(key=lambda e: e.timestamp, reverse=True)
            return events[:limit]

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get_or_create_state(self, ip: str) -> EntityState:
        if ip not in self._entity_states:
            self._entity_states[ip] = EntityState(source_ip=ip)
        return self._entity_states[ip]

    def _try_promote(
        self, state: EntityState, triggering_event: LogEvent
    ) -> Optional[Incident]:
        """
        Promotion gate:
          - At least FAILED_LOGIN_THRESHOLD failed logins (10)
          - Followed by a successful login
          - Followed by privilege escalation (sudo)
          - No existing incident for this entity (prevents duplicate promotion)
        """
        if state.incident_promoted:
            return None

        if not (
            state.has_failed_logins
            and state.has_successful_login
            and state.has_privilege_escalation
        ):
            return None

        # --- Compute final risk score ---
        risk = self._risk_calculator.compute(
            state,
            max_severity=Severity.CRITICAL,
            asset_hostname=triggering_event.hostname,
        )

        # Collect evidence
        alert_ids = [a.alert_id for a in state.alerts]
        techniques = list({a.mitre_technique for a in state.alerts})
        tactics = list({a.mitre_tactic for a in state.alerts})
        hosts = list({e.hostname for e in state.events if e.hostname})
        users = list({e.username for e in state.events if e.username})

        incident = Incident(
            title=f"Multi-Stage Attack Chain Detected from {state.source_ip}",
            description=(
                f"Correlation engine detected a complete attack chain originating "
                f"from {state.source_ip}. The attacker performed {state.failed_login_count} "
                f"failed login attempts, achieved successful authentication, and "
                f"escalated privileges via sudo within a {WINDOW_SECONDS // 60}-minute window."
            ),
            severity=Severity.CRITICAL,
            risk_score=risk,
            source_ip=state.source_ip,
            affected_hosts=hosts,
            affected_users=users,
            alert_ids=alert_ids,
            mitre_techniques=techniques,
            mitre_tactics=tactics,
            attack_chain=[
                f"🔴 Brute Force: {state.failed_login_count} failed logins (T1110)",
                "🟠 Credential Compromise: Successful authentication (T1078)",
                "🔺 Privilege Escalation: sudo command execution (T1548.003)",
            ],
        )

        state.incident_promoted = True
        state.current_risk_score = risk
        self._incidents.append(incident)
        return incident

    @staticmethod
    def _max_severity(alerts: List[Alert]) -> Severity:
        order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        max_sev = Severity.INFO
        for alert in alerts:
            if order.index(alert.severity.value) > order.index(max_sev.value):
                max_sev = alert.severity
        return max_sev

    @staticmethod
    def _event_epoch(event: LogEvent) -> float:
        ts = event.timestamp
        if isinstance(ts, datetime):
            return ts.replace(tzinfo=timezone.utc).timestamp() \
                if ts.tzinfo is None else ts.timestamp()
        return float(ts)

    def _gc_loop(self) -> None:
        """Background thread: purge stale entity states every minute."""
        while True:
            time.sleep(CLEANUP_INTERVAL)
            with self._lock:
                stale_ips = [
                    ip for ip, state in self._entity_states.items()
                    if not state.events and not state.incident_promoted
                ]
                for ip in stale_ips:
                    del self._entity_states[ip]

"""
Unit tests for the Apex-SOC Correlation Engine.
Tests cover:
  - Failed login accumulation
  - Risk score formula accuracy
  - Incident promotion (full chain)
  - No promotion on incomplete chain
  - Duplicate promotion prevention
  - Asset tier weighting
"""
from __future__ import annotations

import pytest

from core.correlation import (
    FAILED_LOGIN_THRESHOLD,
    RiskCalculator,
    CorrelationEngine,
    EntityState,
)
from core.detection import DetectionEngine, RULES
from models.schemas import Alert, LogEvent, LogSource, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(
    source_ip: str = "10.0.0.1",
    username: str = "admin",
    hostname: str = "prod-web-01",
    message: str = "Failed password for admin from 10.0.0.1 port 22 ssh2",
    source: LogSource = LogSource.LINUX_AUTH,
) -> LogEvent:
    return LogEvent(
        source=source,
        source_ip=source_ip,
        username=username,
        hostname=hostname,
        message=message,
    )


def _make_alert(
    mitre_technique: str = "T1110",
    mitre_tactic: str = "Credential Access",
    severity: Severity = Severity.MEDIUM,
    rule_name: str = "Brute Force - Failed Password",
) -> Alert:
    event = _make_event()
    return Alert(
        rule_name=rule_name,
        mitre_technique=mitre_technique,
        mitre_tactic=mitre_tactic,
        severity=severity,
        event=event,
    )


# ---------------------------------------------------------------------------
# Risk Calculator Tests
# ---------------------------------------------------------------------------

class TestRiskCalculator:

    def test_zero_events_gives_zero_freq_component(self):
        state = EntityState(source_ip="1.2.3.4", failed_login_count=0)
        score = RiskCalculator.compute(state, Severity.INFO, "dev-box")
        # severity=0*40 + freq=0*30 + asset(dev=0.25)*30 = 7.5
        assert score == pytest.approx(7.5, abs=0.1)

    def test_high_severity_weight(self):
        state = EntityState(source_ip="1.2.3.4", failed_login_count=0)
        score = RiskCalculator.compute(state, Severity.HIGH, None)
        # 0.75*40 + 0*30 + 0.5*30 = 30 + 15 = 45
        assert score == pytest.approx(45.0, abs=0.1)

    def test_critical_severity_max(self):
        state = EntityState(source_ip="1.2.3.4", failed_login_count=50)
        score = RiskCalculator.compute(state, Severity.CRITICAL, "prod-db-01")
        # 1.0*40 + 1.0*30 + 1.0*30 = 100
        assert score == pytest.approx(100.0, abs=0.1)

    def test_frequency_saturates_at_50(self):
        state = EntityState(source_ip="1.2.3.4", failed_login_count=1000)
        score_saturated = RiskCalculator.compute(state, Severity.INFO, None)
        state2 = EntityState(source_ip="1.2.3.4", failed_login_count=50)
        score_50 = RiskCalculator.compute(state2, Severity.INFO, None)
        assert score_saturated == score_50

    def test_prod_asset_higher_than_dev(self):
        prod_state = EntityState(source_ip="1.2.3.4", failed_login_count=10)
        dev_state = EntityState(source_ip="1.2.3.4", failed_login_count=10)
        prod_score = RiskCalculator.compute(prod_state, Severity.MEDIUM, "prod-api")
        dev_score = RiskCalculator.compute(dev_state, Severity.MEDIUM, "dev-api")
        assert prod_score > dev_score

    def test_score_clamped_to_100(self):
        state = EntityState(source_ip="1.2.3.4", failed_login_count=9999)
        score = RiskCalculator.compute(state, Severity.CRITICAL, "prod-db")
        assert score <= 100.0

    def test_score_never_negative(self):
        state = EntityState(source_ip="1.2.3.4", failed_login_count=0)
        score = RiskCalculator.compute(state, Severity.INFO, "test-server")
        assert score >= 0.0


# ---------------------------------------------------------------------------
# Detection Engine Tests
# ---------------------------------------------------------------------------

class TestDetectionEngine:

    def setup_method(self):
        self.engine = DetectionEngine()

    def test_failed_password_triggers_t1110(self):
        event = _make_event(
            message="Failed password for root from 192.168.1.1 port 22 ssh2"
        )
        alerts = self.engine.analyze(event)
        techniques = [a.mitre_technique for a in alerts]
        assert "T1110" in techniques

    def test_accepted_password_triggers_t1078(self):
        event = _make_event(
            message="Accepted password for user1 from 10.0.0.5 port 22 ssh2"
        )
        alerts = self.engine.analyze(event)
        techniques = [a.mitre_technique for a in alerts]
        assert "T1078" in techniques

    def test_sudo_triggers_privilege_escalation(self):
        event = _make_event(
            message="sudo: user1 : TTY=pts/0 ; PWD=/home/user1 ; USER=root ; COMMAND=/bin/bash"
        )
        alerts = self.engine.analyze(event)
        techniques = [a.mitre_technique for a in alerts]
        assert "T1548.003" in techniques

    def test_sql_injection_nginx_event(self):
        event = _make_event(
            source=LogSource.NGINX,
            message="GET /search?q=' OR '1'='1 HTTP/1.1",
        )
        alerts = self.engine.analyze(event)
        techniques = [a.mitre_technique for a in alerts]
        assert "T1190" in techniques

    def test_source_filter_prevents_match(self):
        # SQL injection pattern should NOT match linux_auth source
        event = _make_event(
            source=LogSource.LINUX_AUTH,
            message="union select 1,2,3 from users",
        )
        alerts = self.engine.analyze(event)
        # T1190 rule has source_filter=nginx, so should not appear
        techniques = [a.mitre_technique for a in alerts]
        assert "T1190" not in techniques

    def test_benign_message_no_alerts(self):
        event = _make_event(message="System booted successfully.")
        alerts = self.engine.analyze(event)
        assert len(alerts) == 0


# ---------------------------------------------------------------------------
# Correlation Engine Tests
# ---------------------------------------------------------------------------

class TestCorrelationEngine:

    def setup_method(self):
        self.engine = CorrelationEngine()

    def _run_failed_logins(self, ip: str, count: int) -> None:
        for _ in range(count):
            event = _make_event(
                source_ip=ip,
                message="Failed password for root from 192.168.1.1 port 22 ssh2",
            )
            alert = _make_alert("T1110", "Credential Access", Severity.MEDIUM)
            alert.event = event
            self.engine.process_alerts(event, [alert])

    def test_no_incident_before_threshold(self):
        ip = "10.10.10.1"
        self._run_failed_logins(ip, FAILED_LOGIN_THRESHOLD - 1)
        assert len(self.engine.get_incidents()) == 0

    def test_no_incident_without_success(self):
        ip = "10.10.10.2"
        self._run_failed_logins(ip, FAILED_LOGIN_THRESHOLD + 5)
        # No successful login → no incident
        assert len(self.engine.get_incidents()) == 0

    def test_no_incident_without_privilege_escalation(self):
        ip = "10.10.10.3"
        self._run_failed_logins(ip, FAILED_LOGIN_THRESHOLD + 5)
        # Successful login
        success_event = _make_event(
            source_ip=ip,
            message="Accepted password for user1 from 10.10.10.3 port 22",
        )
        success_alert = _make_alert("T1078", "Defense Evasion", Severity.HIGH, "Successful Authentication After Failure")
        success_alert.event = success_event
        self.engine.process_alerts(success_event, [success_alert])
        # No sudo → no incident
        assert len(self.engine.get_incidents()) == 0

    def test_full_chain_promotes_incident(self):
        ip = "10.10.10.4"
        # Stage 1: Brute force
        self._run_failed_logins(ip, FAILED_LOGIN_THRESHOLD + 2)
        # Stage 2: Success
        success_event = _make_event(
            source_ip=ip,
            hostname="prod-web-01",
            message="Accepted password for admin from 10.10.10.4 port 22",
        )
        success_alert = _make_alert(
            "T1078", "Defense Evasion", Severity.HIGH, "Successful Authentication After Failure"
        )
        success_alert.event = success_event
        self.engine.process_alerts(success_event, [success_alert])
        # Stage 3: Privilege escalation
        sudo_event = _make_event(
            source_ip=ip,
            hostname="prod-web-01",
            message="sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash",
        )
        sudo_alert = _make_alert(
            "T1548.003", "Privilege Escalation", Severity.HIGH, "Privilege Escalation - Sudo Command"
        )
        sudo_alert.event = sudo_event
        incident = self.engine.process_alerts(sudo_event, [sudo_alert])

        assert incident is not None
        assert incident.severity.value == "CRITICAL"
        assert incident.source_ip == ip
        assert incident.risk_score > 60.0
        assert len(self.engine.get_incidents()) == 1

    def test_no_duplicate_promotion(self):
        ip = "10.10.10.5"
        self._run_failed_logins(ip, FAILED_LOGIN_THRESHOLD + 2)
        success_event = _make_event(
            source_ip=ip,
            message="Accepted password for admin from 10.10.10.5 port 22",
        )
        success_alert = _make_alert("T1078", "Defense Evasion", Severity.HIGH, "Successful Authentication After Failure")
        success_alert.event = success_event
        self.engine.process_alerts(success_event, [success_alert])

        for _ in range(3):
            sudo_event = _make_event(
                source_ip=ip,
                message="sudo: admin : TTY=pts/0 ; USER=root ; COMMAND=/bin/bash",
            )
            sudo_alert = _make_alert("T1548.003", "Privilege Escalation", Severity.HIGH, "Privilege Escalation - Sudo Command")
            sudo_alert.event = sudo_event
            self.engine.process_alerts(sudo_event, [sudo_alert])

        # Only one incident should exist despite multiple sudo attempts
        assert len(self.engine.get_incidents()) == 1

    def test_risk_score_above_minimum_on_promotion(self):
        ip = "10.10.10.6"
        self._run_failed_logins(ip, FAILED_LOGIN_THRESHOLD + 10)
        success_event = _make_event(source_ip=ip, message="Accepted password for user1 from 10.10.10.6 port 22")
        success_alert = _make_alert("T1078", "Defense Evasion", Severity.HIGH, "Successful Authentication After Failure")
        success_alert.event = success_event
        self.engine.process_alerts(success_event, [success_alert])

        sudo_event = _make_event(source_ip=ip, message="sudo: user1 : TTY=pts/0 ; USER=root ; COMMAND=/bin/id")
        sudo_alert = _make_alert("T1548.003", "Privilege Escalation", Severity.HIGH, "Privilege Escalation - Sudo Command")
        sudo_alert.event = sudo_event
        incident = self.engine.process_alerts(sudo_event, [sudo_alert])

        assert incident is not None
        assert 0 < incident.risk_score <= 100.0

    def test_top_ips_returns_results(self):
        ip = "10.10.10.7"
        self._run_failed_logins(ip, 5)
        top = self.engine.get_top_ips(limit=5)
        ips_found = [entry["ip"] for entry in top]
        assert ip in ips_found

    def test_stats_count_events(self):
        ip = "10.10.10.8"
        self._run_failed_logins(ip, 3)
        stats = self.engine.get_stats()
        assert stats["total_events"] >= 3

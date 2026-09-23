"""
Apex-SOC Detection Engine
Sigma-like rule matching with MITRE ATT&CK mapping.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional

from models.schemas import Alert, LogEvent, Severity


# ---------------------------------------------------------------------------
# Rule Definition
# ---------------------------------------------------------------------------

@dataclass
class DetectionRule:
    """A single detection rule modelled after Sigma rule structure."""

    name: str
    description: str
    mitre_technique: str
    mitre_tactic: str
    severity: Severity
    # List of regex patterns - any match triggers the rule
    patterns: List[re.Pattern] = field(default_factory=list)
    # Optional source restriction (None = match all sources)
    source_filter: Optional[str] = None
    tags: List[str] = field(default_factory=list)

    def matches(self, event: LogEvent) -> bool:
        """Return True if any pattern matches the event message."""
        if self.source_filter and event.source.value != self.source_filter:
            return False
        msg = event.message
        return any(p.search(msg) for p in self.patterns)


# ---------------------------------------------------------------------------
# Rule Catalogue
# ---------------------------------------------------------------------------

RULES: List[DetectionRule] = [
    # ---- Credential Access ------------------------------------------------
    DetectionRule(
        name="Brute Force - Failed Password",
        description="Repeated failed SSH/login attempts indicating brute force",
        mitre_technique="T1110",
        mitre_tactic="Credential Access",
        severity=Severity.MEDIUM,
        patterns=[
            re.compile(r"failed password", re.IGNORECASE),
            re.compile(r"authentication failure", re.IGNORECASE),
            re.compile(r"invalid user", re.IGNORECASE),
        ],
        source_filter="linux_auth",
        tags=["brute-force", "ssh"],
    ),
    DetectionRule(
        name="Brute Force - Windows Logon Failure",
        description="Windows Event 4625 - Account failed to log on",
        mitre_technique="T1110",
        mitre_tactic="Credential Access",
        severity=Severity.MEDIUM,
        patterns=[
            re.compile(r"event.?id[=:\s]+4625", re.IGNORECASE),
            re.compile(r"logon failure", re.IGNORECASE),
        ],
        source_filter="windows_event",
        tags=["brute-force", "windows"],
    ),
    DetectionRule(
        name="Successful Authentication After Failure",
        description="Successful login detected - possible credential compromise",
        mitre_technique="T1078",
        mitre_tactic="Defense Evasion",
        severity=Severity.HIGH,
        patterns=[
            re.compile(r"accepted password", re.IGNORECASE),
            re.compile(r"accepted publickey", re.IGNORECASE),
            re.compile(r"session opened for user", re.IGNORECASE),
        ],
        source_filter="linux_auth",
        tags=["valid-account"],
    ),
    # ---- Privilege Escalation --------------------------------------------
    DetectionRule(
        name="Privilege Escalation - Sudo Command",
        description="Sudo execution indicating privilege escalation attempt",
        mitre_technique="T1548.003",
        mitre_tactic="Privilege Escalation",
        severity=Severity.HIGH,
        patterns=[
            re.compile(r"\bsudo\b.+command=", re.IGNORECASE),
            re.compile(r"sudo:.+TTY=", re.IGNORECASE),
        ],
        source_filter="linux_auth",
        tags=["sudo", "privilege-escalation"],
    ),
    DetectionRule(
        name="Privilege Escalation - Windows Event 4672",
        description="Special privileges assigned to new logon (admin rights)",
        mitre_technique="T1548",
        mitre_tactic="Privilege Escalation",
        severity=Severity.HIGH,
        patterns=[
            re.compile(r"event.?id[=:\s]+4672", re.IGNORECASE),
            re.compile(r"special privileges", re.IGNORECASE),
        ],
        source_filter="windows_event",
        tags=["privilege-escalation", "windows"],
    ),
    # ---- Lateral Movement ------------------------------------------------
    DetectionRule(
        name="Lateral Movement - SSH Tunneling",
        description="SSH tunneling or port forwarding detected",
        mitre_technique="T1021.004",
        mitre_tactic="Lateral Movement",
        severity=Severity.HIGH,
        patterns=[
            re.compile(r"direct-tcpip", re.IGNORECASE),
            re.compile(r"port forwarding", re.IGNORECASE),
        ],
        tags=["lateral-movement", "ssh"],
    ),
    # ---- Discovery -------------------------------------------------------
    DetectionRule(
        name="Reconnaissance - Port Scan",
        description="Rapid sequential port access indicating scanning",
        mitre_technique="T1046",
        mitre_tactic="Discovery",
        severity=Severity.MEDIUM,
        patterns=[
            re.compile(r"connection refused", re.IGNORECASE),
            re.compile(r"no route to host", re.IGNORECASE),
        ],
        tags=["recon", "port-scan"],
    ),
    # ---- Initial Access --------------------------------------------------
    DetectionRule(
        name="Web Application Attack - SQL Injection",
        description="SQL injection patterns in web access logs",
        mitre_technique="T1190",
        mitre_tactic="Initial Access",
        severity=Severity.HIGH,
        patterns=[
            re.compile(r"(%27|')\s*(or|and)\s*('|\d)", re.IGNORECASE),
            re.compile(r"union.{0,20}select", re.IGNORECASE),
            re.compile(r"--\s*(#|$)", re.IGNORECASE),
            re.compile(r";\s*drop\s+table", re.IGNORECASE),
        ],
        source_filter="nginx",
        tags=["sqli", "web-attack"],
    ),
    DetectionRule(
        name="Web Application Attack - XSS",
        description="Cross-site scripting attempt in web request",
        mitre_technique="T1059.007",
        mitre_tactic="Execution",
        severity=Severity.MEDIUM,
        patterns=[
            re.compile(r"<script", re.IGNORECASE),
            re.compile(r"javascript:", re.IGNORECASE),
            re.compile(r"onerror\s*=", re.IGNORECASE),
        ],
        source_filter="nginx",
        tags=["xss", "web-attack"],
    ),
    DetectionRule(
        name="Web Application Attack - Path Traversal",
        description="Directory traversal detected in URL",
        mitre_technique="T1083",
        mitre_tactic="Discovery",
        severity=Severity.HIGH,
        patterns=[
            re.compile(r"\.\./", re.IGNORECASE),
            re.compile(r"%2e%2e%2f", re.IGNORECASE),
            re.compile(r"/etc/passwd", re.IGNORECASE),
        ],
        source_filter="nginx",
        tags=["path-traversal", "web-attack"],
    ),
    # ---- Command & Control -----------------------------------------------
    DetectionRule(
        name="C2 - Suspicious Outbound Connection",
        description="Outbound connection to suspicious port (potential C2)",
        mitre_technique="T1071",
        mitre_tactic="Command and Control",
        severity=Severity.HIGH,
        patterns=[
            re.compile(r"port\s+(4444|1337|31337|6666|9001)", re.IGNORECASE),
            re.compile(r"connect.+:4444", re.IGNORECASE),
        ],
        tags=["c2", "malware"],
    ),
    # ---- Persistence -----------------------------------------------------
    DetectionRule(
        name="Persistence - Cron Job Modification",
        description="Crontab modification detected",
        mitre_technique="T1053.003",
        mitre_tactic="Persistence",
        severity=Severity.MEDIUM,
        patterns=[
            re.compile(r"crontab", re.IGNORECASE),
            re.compile(r"/etc/cron", re.IGNORECASE),
        ],
        tags=["persistence", "cron"],
    ),
    # ---- New User Creation -----------------------------------------------
    DetectionRule(
        name="Persistence - New Account Created",
        description="New system account created (potential persistence)",
        mitre_technique="T1136.001",
        mitre_tactic="Persistence",
        severity=Severity.HIGH,
        patterns=[
            re.compile(r"useradd", re.IGNORECASE),
            re.compile(r"new user:", re.IGNORECASE),
            re.compile(r"event.?id[=:\s]+4720", re.IGNORECASE),
        ],
        tags=["persistence", "account-creation"],
    ),
]


# ---------------------------------------------------------------------------
# Detection Engine
# ---------------------------------------------------------------------------

class DetectionEngine:
    """
    Matches normalised log events against the rule catalogue.
    Returns a list of Alert objects for every matching rule.
    """

    def __init__(self, rules: Optional[List[DetectionRule]] = None) -> None:
        self._rules = rules if rules is not None else RULES

    def analyze(self, event: LogEvent) -> List[Alert]:
        """Run event through all rules; return matched alerts."""
        alerts: List[Alert] = []
        for rule in self._rules:
            if rule.matches(event):
                alert = Alert(
                    rule_name=rule.name,
                    mitre_technique=rule.mitre_technique,
                    mitre_tactic=rule.mitre_tactic,
                    severity=rule.severity,
                    event=event,
                    description=rule.description,
                )
                # Enrich the event in-place
                event.mitre_technique = rule.mitre_technique
                event.mitre_tactic = rule.mitre_tactic
                if event.severity.value < rule.severity.value:
                    event.severity = rule.severity
                event.tags.extend(rule.tags)
                alerts.append(alert)
        return alerts


# Module-level singleton
detection_engine = DetectionEngine()

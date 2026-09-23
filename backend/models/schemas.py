"""
Apex-SOC Pydantic Models / Schemas
Covers: LogEvent, Alert, Incident
"""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class LogSource(str, Enum):
    LINUX_AUTH = "linux_auth"
    WINDOWS_EVENT = "windows_event"
    NGINX = "nginx"
    GENERIC = "generic"


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentStatus(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


# ---------------------------------------------------------------------------
# Core Log Event
# ---------------------------------------------------------------------------

class LogEvent(BaseModel):
    """Represents a normalised log event ingested from any source."""

    event_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier assigned at ingest time",
    )
    timestamp: datetime = Field(
        default_factory=datetime.utcnow,
        description="UTC timestamp of the event",
    )
    source: LogSource = Field(
        default=LogSource.GENERIC,
        description="Origin log source type",
    )
    source_ip: Optional[str] = Field(None, description="Source IP address")
    dest_ip: Optional[str] = Field(None, description="Destination IP address")
    username: Optional[str] = Field(None, description="Username associated with event")
    hostname: Optional[str] = Field(None, description="Target hostname")
    message: str = Field(..., description="Raw log message text")
    raw: Optional[Dict[str, Any]] = Field(
        None, description="Original unparsed payload"
    )

    # Enrichment fields (populated by detection engine)
    mitre_technique: Optional[str] = Field(
        None, description="Mapped MITRE ATT&CK technique ID e.g. T1110"
    )
    mitre_tactic: Optional[str] = Field(
        None, description="Parent MITRE tactic e.g. Credential Access"
    )
    severity: Severity = Field(Severity.INFO)
    tags: List[str] = Field(default_factory=list)

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, v: Any) -> datetime:
        if isinstance(v, datetime):
            return v
        if isinstance(v, str):
            return datetime.fromisoformat(v.replace("Z", "+00:00"))
        if isinstance(v, (int, float)):
            return datetime.utcfromtimestamp(v)
        raise ValueError(f"Cannot parse timestamp: {v!r}")

    model_config = {"json_schema_extra": {
        "example": {
            "source": "linux_auth",
            "source_ip": "192.168.1.50",
            "username": "root",
            "hostname": "prod-web-01",
            "message": "Failed password for root from 192.168.1.50 port 22 ssh2",
        }
    }}


# ---------------------------------------------------------------------------
# Alert
# ---------------------------------------------------------------------------

class Alert(BaseModel):
    """A single atomic detection hit produced by the rule engine."""

    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    triggered_at: datetime = Field(default_factory=datetime.utcnow)
    rule_name: str
    mitre_technique: str
    mitre_tactic: str
    severity: Severity
    event: LogEvent
    description: str = ""


# ---------------------------------------------------------------------------
# Incident
# ---------------------------------------------------------------------------

class Incident(BaseModel):
    """
    A correlated, multi-event attack chain promoted by the
    sliding-window correlation engine.
    """

    incident_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    title: str
    description: str
    severity: Severity
    status: IncidentStatus = Field(IncidentStatus.OPEN)

    # Risk score: float in [0, 100]
    risk_score: float = Field(0.0, ge=0.0, le=100.0)

    # Entities involved
    source_ip: Optional[str] = None
    affected_hosts: List[str] = Field(default_factory=list)
    affected_users: List[str] = Field(default_factory=list)

    # Evidence chain
    alert_ids: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    mitre_tactics: List[str] = Field(default_factory=list)

    # Attack chain summary for UI
    attack_chain: List[str] = Field(
        default_factory=list,
        description="Human-readable ordered list of attack stages",
    )


# ---------------------------------------------------------------------------
# API Response Models
# ---------------------------------------------------------------------------

class IngestResponse(BaseModel):
    event_id: str
    alerts_generated: int
    incident_promoted: bool
    incident_id: Optional[str] = None


class DashboardStats(BaseModel):
    total_events: int
    total_incidents: int
    critical_alerts: int
    high_alerts: int
    events_last_hour: int


class TopIP(BaseModel):
    ip: str
    event_count: int
    failed_logins: int
    risk_score: float
    is_flagged: bool

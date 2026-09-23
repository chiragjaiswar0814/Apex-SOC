"""
Apex-SOC Ingest Router
POST /api/ingest - Accepts JSON log events from Linux auth, Windows, and Nginx sources.
"""
from __future__ import annotations

from typing import List

from fastapi import APIRouter, HTTPException, Request, status

from core.detection import detection_engine
from models.schemas import IngestResponse, LogEvent

router = APIRouter()


@router.post(
    "/ingest",
    response_model=IngestResponse,
    status_code=status.HTTP_200_OK,
    summary="Ingest a single log event",
    description=(
        "Accepts a normalised log event payload. "
        "Runs it through the detection engine and correlation engine. "
        "Returns the generated alert count and whether an incident was promoted."
    ),
)
async def ingest_event(event: LogEvent, request: Request) -> IngestResponse:
    """
    Single-event ingest endpoint.
    The correlation engine is accessed via app.state (set during lifespan startup).
    """
    correlation_engine = request.app.state.correlation_engine

    # 1. Run detection rules
    alerts = detection_engine.analyze(event)

    # 2. Feed alerts into the correlation engine
    incident = None
    if alerts:
        incident = correlation_engine.process_alerts(event, alerts)
    else:
        # Still feed the raw event for tracking (e.g. normal auth success)
        correlation_engine.process_alerts(event, [])

    return IngestResponse(
        event_id=event.event_id,
        alerts_generated=len(alerts),
        incident_promoted=incident is not None,
        incident_id=incident.incident_id if incident else None,
    )


@router.post(
    "/ingest/batch",
    status_code=status.HTTP_200_OK,
    summary="Ingest a batch of log events",
    description="Accepts up to 500 log events in a single request.",
)
async def ingest_batch(
    events: List[LogEvent], request: Request
) -> dict:
    """Batch ingest endpoint for high-throughput log shippers."""
    if len(events) > 500:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Batch size exceeds maximum of 500 events.",
        )

    correlation_engine = request.app.state.correlation_engine
    total_alerts = 0
    incidents_promoted = 0

    for event in events:
        alerts = detection_engine.analyze(event)
        total_alerts += len(alerts)
        incident = correlation_engine.process_alerts(event, alerts)
        if incident:
            incidents_promoted += 1

    return {
        "events_processed": len(events),
        "total_alerts_generated": total_alerts,
        "incidents_promoted": incidents_promoted,
    }

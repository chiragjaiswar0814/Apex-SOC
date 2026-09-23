"""
Apex-SOC Dashboard Router
GET /api/stats       - Aggregated event/incident counts
GET /api/incidents   - List of correlated incidents
GET /api/top-ips     - Most aggressive source IPs
GET /api/events      - Recent event stream for timeline chart
"""
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Query, Request

from models.schemas import DashboardStats, Incident, LogEvent, TopIP

router = APIRouter()


@router.get(
    "/stats",
    response_model=DashboardStats,
    summary="Get aggregated dashboard statistics",
)
async def get_stats(request: Request) -> DashboardStats:
    """Returns high-level counts for the top-stat cards."""
    engine = request.app.state.correlation_engine
    raw = engine.get_stats()
    return DashboardStats(**raw)


@router.get(
    "/incidents",
    response_model=List[Incident],
    summary="Get all correlated incidents",
)
async def get_incidents(
    request: Request,
    limit: int = Query(default=50, ge=1, le=500, description="Max incidents to return"),
    severity: Optional[str] = Query(
        default=None,
        description="Filter by severity: INFO | LOW | MEDIUM | HIGH | CRITICAL",
    ),
) -> List[Incident]:
    """Returns the list of correlated incidents, newest first."""
    engine = request.app.state.correlation_engine
    incidents = engine.get_incidents()
    # Filter
    if severity:
        incidents = [i for i in incidents if i.severity.value == severity.upper()]
    # Sort newest first
    incidents.sort(key=lambda i: i.created_at, reverse=True)
    return incidents[:limit]


@router.get(
    "/top-ips",
    response_model=List[TopIP],
    summary="Get top attacker IPs by risk score",
)
async def get_top_ips(
    request: Request,
    limit: int = Query(default=10, ge=1, le=100),
) -> List[TopIP]:
    """Returns the most aggressive source IPs sorted by risk score."""
    engine = request.app.state.correlation_engine
    raw = engine.get_top_ips(limit=limit)
    return [TopIP(**item) for item in raw]


@router.get(
    "/events",
    response_model=List[LogEvent],
    summary="Get recent ingested events for timeline rendering",
)
async def get_events(
    request: Request,
    limit: int = Query(default=200, ge=1, le=1000),
) -> List[LogEvent]:
    """Returns the most recent N events for the frontend timeline chart."""
    engine = request.app.state.correlation_engine
    return engine.get_recent_events(limit=limit)

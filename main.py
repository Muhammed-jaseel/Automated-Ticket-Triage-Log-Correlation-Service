"""FastAPI Triage Webhook & System Status Reporting Service."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, Request

from correlator import correlate_logs, normalize_utc
from database import (
    get_incident,
    get_status_summary,
    init_db,
    list_incidents,
    update_incident_status,
    upsert_incident,
)
from models import IncidentStatus, IncidentStatusUpdate, SystemStatusSummary, TriageReport
from parsers import TicketParseError, parse_ticket_payload
from sla import generate_sla_update


BASE_DIR = Path(__file__).resolve().parent


def get_log_path() -> Path:
    """Resolve the service log file path from environment or project default."""
    return Path(os.getenv("TRIAGE_LOG_PATH", str(BASE_DIR / "app.log")))


def get_db_path() -> Path:
    """Resolve the SQLite database file path from environment or project default."""
    return Path(os.getenv("TRIAGE_DB_PATH", str(BASE_DIR / "incidents.db")))


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Initialize SQLite storage on application startup."""
    init_db(get_db_path())
    yield


app = FastAPI(
    title="Automated Ticket Triage & Log-Correlation Service",
    description=(
        "Ingests JSON/XML support tickets, correlates service logs around reported timestamps "
        "and device IDs, classifies root causes, persists incidents to SQLite, and generates "
        "customer-ready SLA updates."
    ),
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/health")
def health_check() -> dict[str, object]:
    """Report API, log file, and SQLite database readiness."""
    log_path = get_log_path()
    db_path = get_db_path()
    return {
        "status": "ok",
        "log_file_exists": log_path.exists(),
        "log_path": str(log_path),
        "db_path": str(db_path),
    }


@app.post("/ticket", response_model=TriageReport)
async def triage_ticket(request: Request) -> TriageReport:
    """Receive a JSON or XML support ticket, correlate logs, log incident, and build SLA update."""
    raw_body = await request.body()
    content_type = request.headers.get("content-type")

    try:
        ticket = parse_ticket_payload(raw_body, content_type=content_type)
    except TicketParseError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    log_path = get_log_path()
    db_path = get_db_path()
    init_db(db_path)

    try:
        correlation = correlate_logs(
            device_id=ticket.device_id,
            reported_at=ticket.reported_at,
            log_path=log_path,
            window_minutes=ticket.window_minutes,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    triaged_at = datetime.now(timezone.utc)
    sla_update = generate_sla_update(ticket, correlation, triaged_at=triaged_at)

    report = TriageReport(
        ticket_id=ticket.ticket_id,
        device_id=ticket.device_id,
        reported_at=normalize_utc(ticket.reported_at),
        triaged_at=triaged_at,
        status="open",
        input_format=ticket.channel,
        correlation=correlation,
        sla=sla_update,
    )
    upsert_incident(db_path, report, ticket)
    return report


@app.get("/incidents")
def get_incidents(
    root_cause: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    device_id: Optional[str] = Query(default=None),
    status: Optional[IncidentStatus] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
) -> dict[str, object]:
    """List triaged incidents with optional filters."""
    db_path = get_db_path()
    init_db(db_path)
    items = list_incidents(
        db_path,
        root_cause=root_cause,
        severity=severity,
        device_id=device_id,
        status=status,
        limit=limit,
    )
    return {"count": len(items), "incidents": items}


@app.get("/incidents/{ticket_id}")
def get_incident_by_id(ticket_id: str) -> dict[str, object]:
    """Retrieve a single triaged incident report by ticket_id."""
    db_path = get_db_path()
    init_db(db_path)
    incident = get_incident(db_path, ticket_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident '{ticket_id}' not found.")
    return incident


@app.patch("/incidents/{ticket_id}")
def patch_incident_status(ticket_id: str, payload: IncidentStatusUpdate) -> dict[str, object]:
    """Update incident status (open, investigating, mitigated, resolved)."""
    db_path = get_db_path()
    init_db(db_path)
    updated = update_incident_status(db_path, ticket_id, payload.status)
    if updated is None:
        raise HTTPException(status_code=404, detail=f"Incident '{ticket_id}' not found.")
    return updated


@app.get("/status", response_model=SystemStatusSummary)
def system_status_report() -> SystemStatusSummary:
    """Return aggregated System & Support Status Reporting metrics."""
    db_path = get_db_path()
    init_db(db_path)
    return SystemStatusSummary(**get_status_summary(db_path))

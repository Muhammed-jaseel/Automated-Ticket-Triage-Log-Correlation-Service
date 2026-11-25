"""Pydantic data models for the Automated Ticket Triage & Log-Correlation Service."""

from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field


IncidentStatus = Literal["open", "investigating", "mitigated", "resolved"]


class TicketInput(BaseModel):
    """Normalized incoming support ticket parsed from JSON or XML."""

    ticket_id: str = Field(..., min_length=1, description="Unique support ticket identifier.")
    device_id: str = Field(..., min_length=1, description="Target Ring device identifier.")
    reported_at: datetime = Field(..., description="ISO-8601 timestamp when the issue occurred.")
    customer_name: str = Field(..., min_length=1, description="Customer full name.")
    customer_email: str = Field(..., min_length=3, description="Customer contact email.")
    issue_summary: str = Field(..., min_length=1, description="Short description of the customer issue.")
    window_minutes: int = Field(
        default=15,
        ge=1,
        le=1440,
        description="Half-width search window (in minutes) around reported_at.",
    )
    channel: Literal["json", "xml"] = Field(default="json", description="Original payload format.")


class MatchedLogEntry(BaseModel):
    """A single ERROR or CRITICAL log entry correlated to a ticket."""

    timestamp: datetime
    level: Literal["ERROR", "CRITICAL"]
    service: str
    device_id: Optional[str] = None
    correlation_scope: Literal["device_match", "system_wide_critical"]
    message: str
    stack_trace: Optional[str] = None


class CorrelationResult(BaseModel):
    """Root-cause classification and extracted evidence from service logs."""

    root_cause: str
    category_label: str
    severity: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    matched_error_count: int
    extracted_logs: list[MatchedLogEntry]
    engineering_summary: str
    recommended_action: str


class SLAUpdate(BaseModel):
    """Customer-ready SLA response generated from the triage result."""

    sla_tier: str
    response_target_minutes: int
    resolution_target_hours: int
    sla_due_at: datetime
    customer_subject: str
    customer_message: str


class TriageReport(BaseModel):
    """Complete structured triage output returned by POST /ticket."""

    ticket_id: str
    device_id: str
    reported_at: datetime
    triaged_at: datetime
    status: IncidentStatus = "open"
    input_format: Literal["json", "xml"]
    correlation: CorrelationResult
    sla: SLAUpdate


class IncidentStatusUpdate(BaseModel):
    """Payload for updating an incident lifecycle status."""

    status: IncidentStatus


class SystemStatusSummary(BaseModel):
    """Aggregated operational and support reporting metrics."""

    total_incidents: int
    by_status: dict[str, int]
    by_severity: dict[str, int]
    by_root_cause: dict[str, int]
    recent_incidents: list[dict]

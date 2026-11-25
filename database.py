"""SQLite persistence and System & Support Status Reporting queries."""

from __future__ import annotations

import json
import sqlite3
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Optional

from models import IncidentStatus, TicketInput, TriageReport


INCIDENTS_SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    ticket_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    customer_name TEXT NOT NULL,
    customer_email TEXT NOT NULL,
    issue_summary TEXT NOT NULL,
    input_format TEXT NOT NULL,
    reported_at TEXT NOT NULL,
    triaged_at TEXT NOT NULL,
    status TEXT NOT NULL,
    root_cause TEXT NOT NULL,
    category_label TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL,
    matched_error_count INTEGER NOT NULL,
    extracted_logs_json TEXT NOT NULL,
    engineering_summary TEXT NOT NULL,
    recommended_action TEXT NOT NULL,
    sla_tier TEXT NOT NULL,
    sla_due_at TEXT NOT NULL,
    customer_subject TEXT NOT NULL,
    customer_message TEXT NOT NULL
);
"""


@contextmanager
def _connect(db_path: Path) -> Iterator[sqlite3.Connection]:
    """Context-managed SQLite connection with Row factory enabled."""
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db(db_path: Path) -> None:
    """Create the incidents table if it does not already exist."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with _connect(db_path) as conn:
        conn.execute(INCIDENTS_SCHEMA)


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    """Convert an incidents table row into a serializable dict."""
    record = dict(row)
    record["extracted_logs"] = json.loads(record.pop("extracted_logs_json"))
    return record


def upsert_incident(db_path: Path, report: TriageReport, ticket: TicketInput) -> None:
    """Insert or update a triaged incident record in SQLite."""
    extracted_logs_json = json.dumps(
        [entry.model_dump(mode="json") for entry in report.correlation.extracted_logs]
    )

    with _connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO incidents (
                ticket_id, device_id, customer_name, customer_email, issue_summary,
                input_format, reported_at, triaged_at, status, root_cause,
                category_label, severity, confidence, matched_error_count,
                extracted_logs_json, engineering_summary, recommended_action,
                sla_tier, sla_due_at, customer_subject, customer_message
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ticket_id) DO UPDATE SET
                device_id = excluded.device_id,
                customer_name = excluded.customer_name,
                customer_email = excluded.customer_email,
                issue_summary = excluded.issue_summary,
                input_format = excluded.input_format,
                reported_at = excluded.reported_at,
                triaged_at = excluded.triaged_at,
                status = excluded.status,
                root_cause = excluded.root_cause,
                category_label = excluded.category_label,
                severity = excluded.severity,
                confidence = excluded.confidence,
                matched_error_count = excluded.matched_error_count,
                extracted_logs_json = excluded.extracted_logs_json,
                engineering_summary = excluded.engineering_summary,
                recommended_action = excluded.recommended_action,
                sla_tier = excluded.sla_tier,
                sla_due_at = excluded.sla_due_at,
                customer_subject = excluded.customer_subject,
                customer_message = excluded.customer_message
            """,
            (
                report.ticket_id,
                report.device_id,
                ticket.customer_name,
                ticket.customer_email,
                ticket.issue_summary,
                report.input_format,
                report.reported_at.isoformat(),
                report.triaged_at.isoformat(),
                report.status,
                report.correlation.root_cause,
                report.correlation.category_label,
                report.correlation.severity,
                report.correlation.confidence,
                report.correlation.matched_error_count,
                extracted_logs_json,
                report.correlation.engineering_summary,
                report.correlation.recommended_action,
                report.sla.sla_tier,
                report.sla.sla_due_at.isoformat(),
                report.sla.customer_subject,
                report.sla.customer_message,
            ),
        )


def get_incident(db_path: Path, ticket_id: str) -> Optional[dict[str, Any]]:
    """Retrieve a single incident by ticket_id."""
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM incidents WHERE ticket_id = ?", (ticket_id,)
        ).fetchone()
    return _row_to_dict(row) if row else None


def list_incidents(
    db_path: Path,
    root_cause: Optional[str] = None,
    severity: Optional[str] = None,
    device_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """List incidents with optional filters ordered by most recently triaged."""
    filters: list[str] = []
    params: list[Any] = []

    for column, value in (
        ("root_cause", root_cause),
        ("severity", severity),
        ("device_id", device_id),
        ("status", status),
    ):
        if value:
            filters.append(f"{column} = ?")
            params.append(value)

    where_clause = f"WHERE {' AND '.join(filters)}" if filters else ""
    params.append(limit)

    query = f"SELECT * FROM incidents {where_clause} ORDER BY triaged_at DESC LIMIT ?"
    with _connect(db_path) as conn:
        rows = conn.execute(query, params).fetchall()
    return [_row_to_dict(row) for row in rows]


def update_incident_status(
    db_path: Path, ticket_id: str, status: IncidentStatus
) -> Optional[dict[str, Any]]:
    """Update the lifecycle status of an existing incident."""
    with _connect(db_path) as conn:
        cursor = conn.execute(
            "UPDATE incidents SET status = ? WHERE ticket_id = ?",
            (status, ticket_id),
        )
        if cursor.rowcount == 0:
            return None
        row = conn.execute(
            "SELECT * FROM incidents WHERE ticket_id = ?", (ticket_id,)
        ).fetchone()
    return _row_to_dict(row) if row else None


def get_status_summary(db_path: Path) -> dict[str, Any]:
    """Aggregate incident counts for System & Support Status Reporting."""
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT ticket_id, device_id, status, severity, root_cause, sla_tier, triaged_at "
            "FROM incidents ORDER BY triaged_at DESC"
        ).fetchall()

    by_status = Counter(row["status"] for row in rows)
    by_severity = Counter(row["severity"] for row in rows)
    by_root_cause = Counter(row["root_cause"] for row in rows)
    recent = [dict(row) for row in rows[:10]]

    return {
        "total_incidents": len(rows),
        "by_status": dict(by_status),
        "by_severity": dict(by_severity),
        "by_root_cause": dict(by_root_cause),
        "recent_incidents": recent,
    }

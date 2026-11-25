"""Log parser, timestamp/device correlator, and root-cause classifier."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from models import CorrelationResult, MatchedLogEntry


LOG_LINE_PATTERN = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)"
    r"\s*\|\s*(?P<level>DEBUG|INFO|WARNING|WARN|ERROR|CRITICAL)"
    r"\s*\|\s*(?P<service>[a-zA-Z0-9_.-]+)"
    r"\s*\|\s*(?:device=(?P<device>[A-Za-z0-9_-]+)\s*\|\s*)?"
    r"(?P<message>.*)$"
)

SYSTEM_WIDE_DEVICE_TOKENS = {None, "ALL", "SYSTEM", "CLUSTER"}


@dataclass
class RawLogEntry:
    """Internal representation of a single log record with optional stack trace."""

    timestamp: datetime
    level: str
    service: str
    device_id: Optional[str]
    message: str
    stack_trace_lines: list[str] = field(default_factory=list)

    @property
    def stack_trace(self) -> Optional[str]:
        if not self.stack_trace_lines:
            return None
        return "\n".join(self.stack_trace_lines)

    @property
    def searchable_text(self) -> str:
        parts = [self.service, self.message]
        if self.stack_trace_lines:
            parts.extend(self.stack_trace_lines)
        return "\n".join(parts).lower()


@dataclass(frozen=True)
class ClassificationRule:
    """Data-driven root-cause classification rule."""

    root_cause: str
    category_label: str
    severity: str
    keywords: tuple[str, ...]
    engineering_summary: str
    recommended_action: str


CLASSIFICATION_RULES: tuple[ClassificationRule, ...] = (
    ClassificationRule(
        root_cause="DATABASE_TIMEOUT",
        category_label="Database Connectivity & Pool Exhaustion",
        severity="P1 - Critical",
        keywords=(
            "connection pool exhausted",
            "operationalerror",
            "query timeout",
            "db timeout",
            "timeout acquiring connection",
            "deadlock",
            "telemetry-db",
        ),
        engineering_summary=(
            "Database connection pool exhaustion or query timeout detected in the telemetry "
            "persistence tier, preventing device events from being written."
        ),
        recommended_action=(
            "Inspect telemetry-db active connections and slow queries; scale read/write pool "
            "capacity and verify connection leak remediation."
        ),
    ),
    ClassificationRule(
        root_cause="MALFORMED_XML_PAYLOAD",
        category_label="Malformed XML Telemetry Payload",
        severity="P2 - High",
        keywords=(
            "xml.etree.elementtree.parseerror",
            "mismatched tag",
            "malformed xml",
            "xmlsyntaxerror",
            "unclosed token",
            "not well-formed (invalid token)",
        ),
        engineering_summary=(
            "Device firmware emitted a malformed XML payload that failed schema/tag parsing "
            "at the ingestion gateway."
        ),
        recommended_action=(
            "Capture offending raw XML frame, check device firmware version for serialization "
            "regressions, and enable dead-letter quarantine for invalid XML payloads."
        ),
    ),
    ClassificationRule(
        root_cause="MALFORMED_JSON_PAYLOAD",
        category_label="Malformed JSON Telemetry Payload",
        severity="P2 - High",
        keywords=(
            "jsondecodeerror",
            "malformed json",
            "invalid json",
            "expecting ',' delimiter",
            "expecting value",
            "unterminated string",
        ),
        engineering_summary=(
            "Telemetry API rejected a truncated or syntactically invalid JSON payload from "
            "the reporting device."
        ),
        recommended_action=(
            "Verify device payload framing/MTU truncation and inspect gateway request-body "
            "validation logs for firmware regression."
        ),
    ),
    ClassificationRule(
        root_cause="MOTION_ALERT_PIPELINE_FAILURE",
        category_label="Motion Alert & Notification Pipeline Failure",
        severity="P2 - High",
        keywords=(
            "motionalertpipelineerror",
            "motion_alert",
            "motion alert",
            "push_notification",
            "503 service unavailable",
            "clip upload failed",
            "motion-pipeline",
        ),
        engineering_summary=(
            "Motion alert dispatch failed downstream (notification gateway 503 or clip upload "
            "failure), causing delayed or missed customer motion alerts."
        ),
        recommended_action=(
            "Check push-notification worker queue depth and upstream media storage health; "
            "replay failed motion alert jobs from retry DLQ."
        ),
    ),
    ClassificationRule(
        root_cause="DEVICE_AUTH_FAILURE",
        category_label="Device Authentication / Token Expiry",
        severity="P3 - Medium",
        keywords=(
            "401 unauthorized",
            "expired device jwt",
            "token expired",
            "invalid signature",
            "auth-service",
        ),
        engineering_summary=(
            "Device API requests were rejected due to an expired or invalid device JWT token."
        ),
        recommended_action=(
            "Trigger remote device token refresh / re-provisioning and verify auth-service "
            "clock skew and key rotation state."
        ),
    ),
)


def normalize_utc(dt: datetime) -> datetime:
    """Convert a datetime to timezone-aware UTC (naive datetimes default to UTC)."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def parse_log_entries(log_text: str) -> list[RawLogEntry]:
    """Parse structured multi-line service logs into RawLogEntry records."""
    entries: list[RawLogEntry] = []
    current: Optional[RawLogEntry] = None

    for raw_line in log_text.splitlines():
        match = LOG_LINE_PATTERN.match(raw_line)
        if match:
            ts_str = match.group("ts").replace("Z", "+00:00")
            parsed_ts = normalize_utc(datetime.fromisoformat(ts_str))
            level = match.group("level")
            if level == "WARN":
                level = "WARNING"

            current = RawLogEntry(
                timestamp=parsed_ts,
                level=level,
                service=match.group("service"),
                device_id=match.group("device"),
                message=match.group("message").strip(),
            )
            entries.append(current)
        elif current is not None and raw_line.strip():
            current.stack_trace_lines.append(raw_line.rstrip())

    return entries


def _matches_device(entry: RawLogEntry, device_id: str) -> bool:
    """Return True if the log entry explicitly belongs to or mentions the device_id."""
    if entry.device_id == device_id:
        return True
    target = device_id.lower()
    return target in entry.message.lower() or (
        entry.stack_trace is not None and target in entry.stack_trace.lower()
    )


def _classify_entries(
    matched: list[MatchedLogEntry],
    raw_by_key: dict[tuple[datetime, str, str], RawLogEntry],
) -> tuple[ClassificationRule | None, float]:
    """Classify root cause against matched ERROR/CRITICAL entries."""
    device_entries = [m for m in matched if m.correlation_scope == "device_match"]
    pool = device_entries if device_entries else matched

    combined_text = "\n".join(
        raw_by_key[(m.timestamp, m.service, m.message)].searchable_text for m in pool
    )

    best_rule: ClassificationRule | None = None
    best_hits = 0

    for rule in CLASSIFICATION_RULES:
        hits = sum(1 for kw in rule.keywords if kw in combined_text)
        if hits > best_hits:
            best_hits = hits
            best_rule = rule

    if best_rule is None:
        return None, 0.45 if matched else 0.0

    base_conf = 0.78 if device_entries else 0.65
    confidence = min(0.98, round(base_conf + 0.06 * best_hits, 2))
    return best_rule, confidence


def correlate_logs(
    device_id: str,
    reported_at: datetime,
    log_path: Path,
    window_minutes: int = 15,
) -> CorrelationResult:
    """Scan service logs around reported_at/device_id and classify the root cause."""
    if not log_path.exists():
        raise FileNotFoundError(f"Service log file not found at: {log_path}")

    log_text = log_path.read_text(encoding="utf-8")
    entries = parse_log_entries(log_text)

    target_ts = normalize_utc(reported_at)
    delta = timedelta(minutes=window_minutes)
    window_start = target_ts - delta
    window_end = target_ts + delta

    matched: list[MatchedLogEntry] = []
    raw_lookup: dict[tuple[datetime, str, str], RawLogEntry] = {}

    for entry in entries:
        if entry.level not in {"ERROR", "CRITICAL"}:
            continue
        if not (window_start <= entry.timestamp <= window_end):
            continue

        if _matches_device(entry, device_id):
            scope = "device_match"
        elif entry.level == "CRITICAL" and entry.device_id in SYSTEM_WIDE_DEVICE_TOKENS:
            scope = "system_wide_critical"
        else:
            continue

        matched_entry = MatchedLogEntry(
            timestamp=entry.timestamp,
            level=entry.level,  # type: ignore[arg-type]
            service=entry.service,
            device_id=entry.device_id,
            correlation_scope=scope,  # type: ignore[arg-type]
            message=entry.message,
            stack_trace=entry.stack_trace,
        )
        matched.append(matched_entry)
        raw_lookup[(entry.timestamp, entry.service, entry.message)] = entry

    if not matched:
        return CorrelationResult(
            root_cause="NO_CORRELATED_ERRORS",
            category_label="No Correlated Service Errors Found",
            severity="P4 - Low",
            confidence=0.25,
            matched_error_count=0,
            extracted_logs=[],
            engineering_summary=(
                f"No ERROR or CRITICAL log entries matched device {device_id} within "
                f"+/-{window_minutes} minutes of {target_ts.isoformat()}."
            ),
            recommended_action=(
                "Verify device local Wi-Fi/power telemetry, confirm timestamp timezone, "
                "or expand search window_minutes."
            ),
        )

    rule, confidence = _classify_entries(matched, raw_lookup)
    if rule is None:
        return CorrelationResult(
            root_cause="UNCLASSIFIED_SERVICE_ERROR",
            category_label="Unclassified Service Error",
            severity="P3 - Medium",
            confidence=confidence,
            matched_error_count=len(matched),
            extracted_logs=matched,
            engineering_summary=(
                f"Found {len(matched)} ERROR/CRITICAL log entries around {target_ts.isoformat()}, "
                "but no known failure signature matched."
            ),
            recommended_action=(
                "Escalate extracted stack traces to on-call platform engineer for manual triage."
            ),
        )

    return CorrelationResult(
        root_cause=rule.root_cause,
        category_label=rule.category_label,
        severity=rule.severity,
        confidence=confidence,
        matched_error_count=len(matched),
        extracted_logs=matched,
        engineering_summary=rule.engineering_summary,
        recommended_action=rule.recommended_action,
    )

"""Unit tests for log parsing, correlation, and root-cause classification."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from correlator import correlate_logs, parse_log_entries


APP_LOG = Path(__file__).resolve().parent.parent / "app.log"


def test_parse_log_entries_preserves_multiline_traces() -> None:
    entries = parse_log_entries(APP_LOG.read_text(encoding="utf-8"))
    error_entries = [e for e in entries if e.level in {"ERROR", "CRITICAL"}]
    assert len(error_entries) >= 5
    assert any(e.stack_trace and "psycopg2.OperationalError" in e.stack_trace for e in error_entries)


def test_correlate_database_timeout_with_system_wide_critical() -> None:
    result = correlate_logs(
        device_id="RING-CAM-1042",
        reported_at=datetime(2026, 11, 25, 8, 13, 0, tzinfo=timezone.utc),
        log_path=APP_LOG,
        window_minutes=15,
    )
    assert result.root_cause == "DATABASE_TIMEOUT"
    assert result.severity == "P1 - Critical"
    assert result.matched_error_count == 2
    scopes = {entry.correlation_scope for entry in result.extracted_logs}
    assert scopes == {"device_match", "system_wide_critical"}


def test_correlate_malformed_xml_payload() -> None:
    result = correlate_logs(
        device_id="RING-DOOR-2088",
        reported_at=datetime(2026, 11, 25, 9, 38, 0, tzinfo=timezone.utc),
        log_path=APP_LOG,
        window_minutes=15,
    )
    assert result.root_cause == "MALFORMED_XML_PAYLOAD"
    assert result.severity == "P2 - High"
    assert result.matched_error_count == 1
    assert "ParseError: mismatched tag" in (result.extracted_logs[0].stack_trace or "")


def test_correlate_malformed_json_payload() -> None:
    result = correlate_logs(
        device_id="RING-FLOOD-5011",
        reported_at=datetime(2026, 11, 25, 10, 24, 0, tzinfo=timezone.utc),
        log_path=APP_LOG,
        window_minutes=15,
    )
    assert result.root_cause == "MALFORMED_JSON_PAYLOAD"
    assert result.severity == "P2 - High"
    assert "JSONDecodeError" in (result.extracted_logs[0].stack_trace or "")


def test_correlate_motion_alert_pipeline_failure() -> None:
    result = correlate_logs(
        device_id="RING-CHIME-3015",
        reported_at=datetime(2026, 11, 25, 11, 12, 0, tzinfo=timezone.utc),
        log_path=APP_LOG,
        window_minutes=15,
    )
    assert result.root_cause == "MOTION_ALERT_PIPELINE_FAILURE"
    assert result.severity == "P2 - High"


def test_correlate_device_auth_failure() -> None:
    result = correlate_logs(
        device_id="RING-ALARM-4090",
        reported_at=datetime(2026, 11, 25, 12, 5, 0, tzinfo=timezone.utc),
        log_path=APP_LOG,
        window_minutes=15,
    )
    assert result.root_cause == "DEVICE_AUTH_FAILURE"
    assert result.severity == "P3 - Medium"


def test_correlate_no_errors_outside_window() -> None:
    result = correlate_logs(
        device_id="RING-CAM-1042",
        reported_at=datetime(2026, 11, 25, 15, 0, 0, tzinfo=timezone.utc),
        log_path=APP_LOG,
        window_minutes=10,
    )
    assert result.root_cause == "NO_CORRELATED_ERRORS"
    assert result.matched_error_count == 0
    assert result.extracted_logs == []

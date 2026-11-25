"""Integration tests for FastAPI triage webhook, XML/JSON parsing, and SQLite reporting."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from main import app


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAMPLES_DIR = PROJECT_ROOT / "samples"


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    db_file = tmp_path / "test_incidents.db"
    monkeypatch.setenv("TRIAGE_DB_PATH", str(db_file))
    monkeypatch.setenv("TRIAGE_LOG_PATH", str(PROJECT_ROOT / "app.log"))
    with TestClient(app) as test_client:
        yield test_client


def test_health_endpoint(client: TestClient) -> None:
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["log_file_exists"] is True


def test_post_json_ticket_db_timeout_and_persistence(client: TestClient) -> None:
    payload = (SAMPLES_DIR / "ticket_db_timeout.json").read_text(encoding="utf-8")
    resp = client.post(
        "/ticket",
        content=payload,
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["ticket_id"] == "TKT-2026-1001"
    assert data["input_format"] == "json"
    assert data["correlation"]["root_cause"] == "DATABASE_TIMEOUT"
    assert data["correlation"]["severity"] == "P1 - Critical"
    assert data["sla"]["sla_tier"] == "Tier-1 Critical"
    assert "Alex Rivera" in data["sla"]["customer_message"]
    assert "Traceback" not in data["sla"]["customer_message"]

    # Verify SQLite persistence and status reporting
    fetched = client.get("/incidents/TKT-2026-1001")
    assert fetched.status_code == 200
    assert fetched.json()["root_cause"] == "DATABASE_TIMEOUT"


def test_post_xml_ticket_malformed_xml_correlation(client: TestClient) -> None:
    xml_payload = (SAMPLES_DIR / "ticket_malformed_xml.xml").read_text(encoding="utf-8")
    resp = client.post(
        "/ticket",
        content=xml_payload,
        headers={"Content-Type": "application/xml"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["ticket_id"] == "TKT-2026-1002"
    assert data["input_format"] == "xml"
    assert data["correlation"]["root_cause"] == "MALFORMED_XML_PAYLOAD"
    assert "Priya Nair" in data["sla"]["customer_message"]


def test_status_reporting_and_incident_lifecycle(client: TestClient) -> None:
    for sample_name, content_type in (
        ("ticket_db_timeout.json", "application/json"),
        ("ticket_malformed_xml.xml", "application/xml"),
        ("ticket_malformed_json.json", "application/json"),
        ("ticket_motion_alert.json", "application/json"),
    ):
        body = (SAMPLES_DIR / sample_name).read_text(encoding="utf-8")
        res = client.post("/ticket", content=body, headers={"Content-Type": content_type})
        assert res.status_code == 200

    # Update one incident status
    patch_resp = client.patch("/incidents/TKT-2026-1002", json={"status": "mitigated"})
    assert patch_resp.status_code == 200
    assert patch_resp.json()["status"] == "mitigated"

    # Filter list
    filtered = client.get("/incidents", params={"root_cause": "MALFORMED_JSON_PAYLOAD"})
    assert filtered.status_code == 200
    assert filtered.json()["count"] == 1
    assert filtered.json()["incidents"][0]["ticket_id"] == "TKT-2026-1003"

    # System status summary
    summary = client.get("/status")
    assert summary.status_code == 200
    summary_body = summary.json()
    assert summary_body["total_incidents"] == 4
    assert summary_body["by_status"]["mitigated"] == 1
    assert summary_body["by_status"]["open"] == 3
    assert summary_body["by_root_cause"]["DATABASE_TIMEOUT"] == 1


def test_rejects_malformed_payloads_and_xxe(client: TestClient) -> None:
    bad_json = client.post(
        "/ticket",
        content='{"ticket_id": "BAD-1"',
        headers={"Content-Type": "application/json"},
    )
    assert bad_json.status_code == 400

    bad_xml = client.post(
        "/ticket",
        content="<ticket><ticket_id>BAD-2</ticket>",
        headers={"Content-Type": "application/xml"},
    )
    assert bad_xml.status_code == 400

    xxe_xml = client.post(
        "/ticket",
        content='<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><ticket/>',
        headers={"Content-Type": "application/xml"},
    )
    assert xxe_xml.status_code == 400

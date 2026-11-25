# Automated Ticket Triage & Log-Correlation Service

A lightweight, local-first support engineering & SRE automation service built with **Python**, **FastAPI**, and **SQLite**. It ingests incoming JSON or XML support tickets, correlates them against service telemetry logs (`app.log`) around the reported timestamp and device ID, extracts `ERROR` / `CRITICAL` stack traces, classifies root causes, persists incidents for status reporting, and generates customer-ready SLA updates.

## Architecture

```text
  JSON / XML Ticket (POST /ticket)
                │
                ▼
     parsers.py (JSON + safe XML)
                │
                ▼
     correlator.py ◄── app.log (multi-line stack traces, motion alerts, DB timeouts)
                │
                ├──► sla.py (SLA tier + customer-safe update)
                └──► database.py (SQLite incidents.db) ──► GET /incidents & GET /status
```

### Key Components

| File | Responsibility |
| --- | --- |
| `app.log` | Mock telemetry/API service logs (motion alerts, DB connection pool timeouts, malformed XML/JSON payloads, expired device JWTs). |
| `parsers.py` | Parses and validates both **JSON** and **XML** ticket payloads (`DOCTYPE`/`ENTITY` declarations blocked). |
| `correlator.py` | Groups multi-line stack traces, filters by `±window_minutes` and `device_id` (plus system-wide `CRITICAL` events), and classifies root causes. |
| `sla.py` | Maps severity (`P1`–`P4`) to SLA response/resolution targets and builds ready-to-send customer SLA notifications without leaking raw stack traces. |
| `database.py` | Stores triaged incidents in SQLite (`incidents.db`) and powers status reporting queries. |
| `main.py` | FastAPI webhook (`POST /ticket`) and incident reporting endpoints (`GET /incidents`, `GET /incidents/{ticket_id}`, `PATCH /incidents/{ticket_id}`, `GET /status`, `GET /health`). |

## Quick Start (< 5 Minutes)

1. **Create a virtual environment and install dependencies**
   ```bash
   python -m venv .venv
   # Windows PowerShell:
   .venv\Scripts\Activate.ps1
   # macOS/Linux:
   # source .venv/bin/activate

   pip install -r requirements.txt
   ```

2. **Start the FastAPI service**
   ```bash
   uvicorn main:app --reload
   ```
   Interactive API docs will be available at `http://127.0.0.1:8000/docs`.

3. **Send sample JSON & XML tickets**

   JSON ticket (Database Timeout correlation):
   ```bash
   curl -X POST http://127.0.0.1:8000/ticket \
     -H "Content-Type: application/json" \
     -d @samples/ticket_db_timeout.json
   ```

   XML ticket (Malformed XML correlation):
   ```bash
   curl -X POST http://127.0.0.1:8000/ticket \
     -H "Content-Type: application/xml" \
     -d @samples/ticket_malformed_xml.xml
   ```

4. **Check System & Support Status Reporting**
   ```bash
   curl http://127.0.0.1:8000/status
   curl http://127.0.0.1:8000/incidents
   ```

## Running Tests

```bash
pytest -v
```

## Configuration

| Environment Variable | Default | Description |
| --- | --- | --- |
| `TRIAGE_LOG_PATH` | `./app.log` | Path to the service log file scanned by `correlator.py`. |
| `TRIAGE_DB_PATH` | `./incidents.db` | Path to the SQLite database file used by `database.py`. |

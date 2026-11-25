"""Unified JSON and XML support ticket payload parser."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from typing import Any

from pydantic import ValidationError

from models import TicketInput


class TicketParseError(ValueError):
    """Raised when an incoming JSON or XML ticket payload cannot be parsed or validated."""


def _detect_format(raw_text: str, content_type: str | None) -> str:
    """Determine whether the payload should be parsed as JSON or XML."""
    normalized_ct = (content_type or "").split(";")[0].strip().lower()
    if normalized_ct in {"application/json", "text/json"}:
        return "json"
    if normalized_ct in {"application/xml", "text/xml"}:
        return "xml"

    stripped = raw_text.lstrip()
    if stripped.startswith("<"):
        return "xml"
    return "json"


def _parse_json_ticket(raw_text: str) -> TicketInput:
    """Parse and validate a JSON support ticket payload."""
    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise TicketParseError(f"Malformed JSON payload: {exc.msg} at line {exc.lineno}, col {exc.colno}") from exc

    if not isinstance(payload, dict):
        raise TicketParseError("JSON payload must be a JSON object.")

    payload["channel"] = "json"
    try:
        return TicketInput(**payload)
    except ValidationError as exc:
        raise TicketParseError(f"Invalid ticket fields: {exc.errors()}") from exc


def _parse_xml_ticket(raw_text: str) -> TicketInput:
    """Parse and validate an XML support ticket payload safely."""
    upper_text = raw_text.upper()
    if "<!DOCTYPE" in upper_text or "<!ENTITY" in upper_text:
        raise TicketParseError("XML DOCTYPE and ENTITY declarations are not permitted.")

    try:
        root = ET.fromstring(raw_text)
    except ET.ParseError as exc:
        raise TicketParseError(f"Malformed XML payload: {exc}") from exc

    if root.tag != "ticket":
        raise TicketParseError(f"Expected root XML element <ticket>, got <{root.tag}>.")

    data: dict[str, Any] = {}
    for child in root:
        if child.text is not None:
            data[child.tag] = child.text.strip()

    if "window_minutes" in data:
        try:
            data["window_minutes"] = int(data["window_minutes"])
        except ValueError as exc:
            raise TicketParseError("XML field <window_minutes> must be an integer.") from exc

    data["channel"] = "xml"
    try:
        return TicketInput(**data)
    except ValidationError as exc:
        raise TicketParseError(f"Invalid XML ticket fields: {exc.errors()}") from exc


def parse_ticket_payload(raw_body: bytes, content_type: str | None = None) -> TicketInput:
    """Decode and parse a raw HTTP request body into a normalized TicketInput."""
    if not raw_body or not raw_body.strip():
        raise TicketParseError("Request body is empty.")

    try:
        raw_text = raw_body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TicketParseError("Request body must be valid UTF-8 text.") from exc

    fmt = _detect_format(raw_text, content_type)
    if fmt == "xml":
        return _parse_xml_ticket(raw_text)
    return _parse_json_ticket(raw_text)

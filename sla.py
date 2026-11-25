"""SLA calculation and customer-ready status notification generator."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from correlator import normalize_utc
from models import CorrelationResult, SLAUpdate, TicketInput


@dataclass(frozen=True)
class SLAPolicy:
    """Response and resolution SLA targets for a severity level."""

    sla_tier: str
    response_target_minutes: int
    resolution_target_hours: int


SLA_POLICIES: dict[str, SLAPolicy] = {
    "P1 - Critical": SLAPolicy(sla_tier="Tier-1 Critical", response_target_minutes=15, resolution_target_hours=2),
    "P2 - High": SLAPolicy(sla_tier="Tier-2 High", response_target_minutes=30, resolution_target_hours=4),
    "P3 - Medium": SLAPolicy(sla_tier="Tier-3 Standard", response_target_minutes=240, resolution_target_hours=24),
    "P4 - Low": SLAPolicy(sla_tier="Tier-4 Low", response_target_minutes=480, resolution_target_hours=48),
}

DEFAULT_POLICY = SLA_POLICIES["P3 - Medium"]

CUSTOMER_EXPLANATIONS: dict[str, tuple[str, str]] = {
    "DATABASE_TIMEOUT": (
        "a temporary telemetry database connectivity delay affecting event recording",
        "Our infrastructure team has been paged and is stabilizing database capacity.",
    ),
    "MALFORMED_XML_PAYLOAD": (
        "a telemetry message formatting issue from your device's event stream",
        "Our device reliability team is reviewing the telemetry framing and firmware compatibility.",
    ),
    "MALFORMED_JSON_PAYLOAD": (
        "a corrupted or incomplete telemetry payload sent by the device",
        "Our platform team is inspecting gateway ingestion logs and will advise on any firmware step.",
    ),
    "MOTION_ALERT_PIPELINE_FAILURE": (
        "a temporary disruption in our motion alert notification delivery pipeline",
        "Our engineering team is re-processing queued alerts and restoring full delivery speed.",
    ),
    "DEVICE_AUTH_FAILURE": (
        "an expired security session token between your device and Ring cloud services",
        "We are issuing a credential refresh and will guide you if a device reboot is needed.",
    ),
    "UNCLASSIFIED_SERVICE_ERROR": (
        "an unexpected cloud service error detected around the time of your report",
        "An on-call engineer is actively reviewing the correlated diagnostics.",
    ),
    "NO_CORRELATED_ERRORS": (
        "no cloud-side service outage during the reported timeframe",
        "A support specialist will walk through local Wi-Fi, power, and device health checks with you.",
    ),
}


def generate_sla_update(
    ticket: TicketInput,
    correlation: CorrelationResult,
    triaged_at: datetime,
) -> SLAUpdate:
    """Build a structured SLA commitment and ready-to-send customer update."""
    policy = SLA_POLICIES.get(correlation.severity, DEFAULT_POLICY)
    reported_utc = normalize_utc(ticket.reported_at)
    sla_due_at = reported_utc + timedelta(minutes=policy.response_target_minutes)

    cause_phrase, next_step = CUSTOMER_EXPLANATIONS.get(
        correlation.root_cause,
        (
            "a service issue currently under investigation",
            "Our support engineering team is reviewing your case.",
        ),
    )

    subject = f"[{ticket.ticket_id}] Service Update for Device {ticket.device_id} ({policy.sla_tier})"
    message = (
        f"Hello {ticket.customer_name},\n\n"
        f"Thank you for contacting Ring Support regarding ticket {ticket.ticket_id} "
        f"for device {ticket.device_id} (reported at {reported_utc.strftime('%Y-%m-%d %H:%M:%S UTC')}).\n\n"
        f"Automated Triage Summary:\n"
        f"- Priority: {correlation.severity} ({policy.sla_tier})\n"
        f"- Initial Finding: Our diagnostics identified {cause_phrase}.\n"
        f"- Current Action: {next_step}\n\n"
        f"SLA Commitment:\n"
        f"- Engineering Response Target: {policy.response_target_minutes} minutes "
        f"(by {sla_due_at.strftime('%Y-%m-%d %H:%M:%S UTC')})\n"
        f"- Target Resolution Window: Within {policy.resolution_target_hours} hours\n\n"
        f"We will send your next update as soon as mitigation is confirmed.\n"
        f"Best regards,\n"
        f"Ring Support & Reliability Automation"
    )

    return SLAUpdate(
        sla_tier=policy.sla_tier,
        response_target_minutes=policy.response_target_minutes,
        resolution_target_hours=policy.resolution_target_hours,
        sla_due_at=sla_due_at,
        customer_subject=subject,
        customer_message=message,
    )

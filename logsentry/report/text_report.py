"""Plain-text report renderer — deterministic, no wall-clock."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

from .. import __version__
from ..models import Alert, LoginEvent, Severity
from ..parsers.base import ParseResult
from .json_report import entities_object, severity_counts


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat()


def _primary_entity(alert: Alert) -> str:
    obj = entities_object(alert)
    if alert.rule_id == "R1":
        return str(obj.get("source_ip", ""))
    if alert.rule_id == "R2":
        return f"{obj.get('username', '')}@{obj.get('source_ip', '')}"
    if alert.rule_id == "R3":
        return (
            f"{obj.get('username', '')}: "
            f"{obj.get('source_ip_from', '')}->{obj.get('source_ip_to', '')}"
        )
    if alert.rule_id in ("R4", "R5"):
        return str(obj.get("username", ""))
    if alert.rule_id == "R0":
        return str(obj.get("entity", ""))
    return ",".join(alert.entities)


def render_text(
    results: Sequence[ParseResult],
    events: Sequence[LoginEvent],
    alerts: Sequence[Alert],
    now: datetime,
    timeline: bool = False,
) -> str:
    """Render a deterministic text report; optionally append a timeline."""
    lines: list[str] = []
    lines.append("LogSentry report")
    lines.append(f"tool_version: {__version__}")
    lines.append(f"generated_at: {_iso(now)}")
    lines.append(f"total_events: {len(events)}")
    lines.append(f"total_alerts: {len(alerts)}")

    counts = severity_counts(alerts)
    by_sev = "  ".join(f"{s.name}={counts[s.name]}" for s in Severity)
    lines.append(f"by_severity: {by_sev}")
    lines.append("")

    lines.append("Alerts (ranked):")
    if not alerts:
        lines.append("  (none)")
    else:
        lines.append(
            "  rank  severity  score  rule  time_range"
            "                                   entity  description"
        )
        for rank, alert in enumerate(alerts, start=1):
            tr = f"{_iso(alert.time_range[0])}..{_iso(alert.time_range[1])}"
            lines.append(
                f"  {rank:<4}  {alert.severity.name:<8}  {alert.score:<5}  "
                f"{alert.rule_id:<4}  {tr}  {_primary_entity(alert)}  "
                f"{alert.description}"
            )

    if timeline:
        lines.append("")
        lines.append("Timeline:")
        if not events:
            lines.append("  (no events)")
        cited = _evidence_markers(alerts)
        ordered = sorted(
            events, key=lambda e: (e.timestamp, e.source_file, e.line_no)
        )
        for ev in ordered:
            marker = cited.get(ev.event_id, "")
            suffix = f"  {marker}" if marker else ""
            lines.append(
                f"  {_iso(ev.timestamp)}  {ev.outcome.name:<12}  "
                f"{ev.auth_method.name:<9}  "
                f"{ev.username or '-'}@{ev.source_ip or '-'}  "
                f"[{ev.source_file}:{ev.line_no}]{suffix}"
            )

    return "\n".join(lines) + "\n"


def _evidence_markers(alerts: Sequence[Alert]) -> dict[str, str]:
    """Map each cited event_id to a deterministic ``*R1 *R3`` marker string."""
    rules_by_event: dict[str, set[str]] = {}
    for alert in alerts:
        for event_id in alert.evidence:
            rules_by_event.setdefault(event_id, set()).add(alert.rule_id)
    return {
        event_id: " ".join(f"*{rid}" for rid in sorted(rules))
        for event_id, rules in rules_by_event.items()
    }

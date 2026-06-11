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
        for ev in events:
            lines.append(
                f"  {_iso(ev.timestamp)}  {ev.outcome.name:<12}  "
                f"{ev.auth_method.name:<9}  "
                f"{ev.username or '-'}@{ev.source_ip or '-'}  "
                f"[{ev.source_file}:{ev.line_no}]"
            )

    return "\n".join(lines) + "\n"

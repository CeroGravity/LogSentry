"""JSON report renderer — byte-deterministic given a fixed ``now``."""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime

from .. import __version__
from ..models import (
    Alert,
    AlertDetail,
    GeoDetail,
    GeoPoint,
    LoginEvent,
    NewSourceIPDetail,
    OffHoursDetail,
    Severity,
)
from ..parsers.base import ParseResult

SCHEMA_VERSION = "1"


def _iso(dt: datetime) -> str:
    """ISO8601 in UTC (always offset-aware, normalized to +00:00)."""
    return dt.astimezone(UTC).isoformat()


def entities_object(alert: Alert) -> dict[str, object]:
    """Reconstruct a structured entities object from an alert's entity tuple.

    R1 encodes ``(*usernames_sorted, ip)``; R2 encodes ``(username, ip)``.
    """
    if alert.rule_id == "R1":
        *users, ip = alert.entities
        return {"source_ip": ip, "usernames": list(users)}
    if alert.rule_id == "R2":
        username, source_ip = alert.entities
        return {"username": username, "source_ip": source_ip}
    if alert.rule_id == "R3":
        username, ip_from, ip_to = alert.entities
        return {"username": username, "source_ip_from": ip_from,
                "source_ip_to": ip_to}
    if alert.rule_id in ("R4", "R5"):
        username, source_ip = alert.entities
        return {"username": username, "source_ip": source_ip}
    return {"values": list(alert.entities)}


def severity_counts(alerts: Sequence[Alert]) -> dict[str, int]:
    """Count alerts per severity name (all severities present, zero-filled)."""
    counts = {s.name: 0 for s in Severity}
    for alert in alerts:
        counts[alert.severity.name] += 1
    return counts


def _geo_point_obj(point: GeoPoint) -> dict[str, object]:
    return {
        "ip": point.ip,
        "lat": point.lat,
        "lon": point.lon,
        "country": point.country,
        "city": point.city,
    }


def _details_obj(detail: AlertDetail) -> dict[str, object]:
    """Serialize a rule-specific detail, type-dispatched (sorted keys upstream).

    R3 ``GeoDetail``: ``distance_km`` -> 1 dp, speeds int. R4 ``OffHoursDetail``
    and R5 ``NewSourceIPDetail`` echo their fields.
    """
    if isinstance(detail, GeoDetail):
        return {
            "src": _geo_point_obj(detail.src),
            "dst": _geo_point_obj(detail.dst),
            "distance_km": round(detail.distance_km, 1),
            "delta_seconds": int(detail.delta_seconds),
            "implied_kmh": int(detail.implied_kmh),
        }
    if isinstance(detail, OffHoursDetail):
        return {
            "local_time": detail.local_time,
            "weekday": detail.weekday,
            "business_window": detail.business_window,
            "non_business_day": detail.non_business_day,
        }
    assert isinstance(detail, NewSourceIPDetail)
    return {
        "new_ip": detail.new_ip,
        "known_ip_count": int(detail.known_ip_count),
    }


def _alert_obj(alert: Alert) -> dict[str, object]:
    obj: dict[str, object] = {
        "alert_id": alert.alert_id,
        "rule_id": alert.rule_id,
        "title": alert.title,
        "severity": alert.severity.name,
        "score": alert.score,
        "time_range": [_iso(alert.time_range[0]), _iso(alert.time_range[1])],
        "entities": entities_object(alert),
        "evidence": list(alert.evidence),
        "description": alert.description,
        "dedup_key": alert.dedup_key,
    }
    # Additive: only alerts carrying details (R3) emit the key. R1/R2 unchanged.
    if alert.details is not None:
        obj["details"] = _details_obj(alert.details)
    return obj


def build_report_obj(
    results: Sequence[ParseResult],
    events: Sequence[LoginEvent],
    alerts: Sequence[Alert],
    now: datetime,
) -> dict[str, object]:
    """Assemble the JSON-serializable report object (deterministic ordering)."""
    inputs = sorted(
        (
            {
                "source_file": r.source_file,
                "event_count": len(r.events),
                "error_count": len(r.errors),
            }
            for r in results
        ),
        key=lambda d: str(d["source_file"]),
    )
    indexed_errors = [
        (r.source_file, err.line_no, err)
        for r in results
        for err in r.errors
    ]
    indexed_errors.sort(key=lambda t: (t[0], t[1]))
    parse_errors: list[dict[str, object]] = [
        {
            "source_file": source_file,
            "line_no": err.line_no,
            "reason": err.reason,
            "fatal": err.fatal,
        }
        for source_file, _line_no, err in indexed_errors
    ]

    return {
        "schema_version": SCHEMA_VERSION,
        "tool_version": __version__,
        "generated_at": _iso(now),
        "inputs": inputs,
        "summary": {
            "total_events": len(events),
            "total_alerts": len(alerts),
            "by_severity": severity_counts(alerts),
        },
        "alerts": [_alert_obj(a) for a in alerts],
        "parse_errors": parse_errors,
    }


def render_json(
    results: Sequence[ParseResult],
    events: Sequence[LoginEvent],
    alerts: Sequence[Alert],
    now: datetime,
) -> str:
    """Render the report as deterministic JSON text."""
    obj = build_report_obj(results, events, alerts, now)
    return json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=False)

"""Tests for optional cross-rule correlation (R0)."""

from __future__ import annotations

from datetime import UTC, datetime

from logsentry.engine import correlate
from logsentry.models import Alert, Severity


def _alert(rule_id: str, sev: Severity, score: float, entity: str,
           start: datetime, end: datetime) -> Alert:
    return Alert(
        alert_id=f"{rule_id}-{entity}",
        rule_id=rule_id,
        title="t",
        severity=sev,
        score=score,
        time_range=(start, end),
        entities=(entity, "1.2.3.4"),
        evidence=("ev",),
        description="d",
        dedup_key=f"{rule_id}:{entity}",
    )


_T0 = datetime(2026, 1, 10, 10, 0, tzinfo=UTC)
_T1 = datetime(2026, 1, 10, 11, 0, tzinfo=UTC)


def test_no_correlation_below_min_rules() -> None:
    # Two alerts but same rule_id -> only 1 distinct rule -> no R0.
    alerts = (
        _alert("R2", Severity.CRITICAL, 90, "alice", _T0, _T0),
        _alert("R2", Severity.CRITICAL, 90, "alice", _T1, _T1),
    )
    assert correlate(alerts, min_rules=2) == ()


def test_correlated_alert_fields() -> None:
    alerts = (
        _alert("R4", Severity.MEDIUM, 60, "alice", _T0, _T0),
        _alert("R2", Severity.CRITICAL, 90, "alice", _T1, _T1),
    )
    out = correlate(alerts, min_rules=2)
    assert len(out) == 1
    r0 = out[0]
    assert r0.rule_id == "R0"
    assert r0.severity is Severity.CRITICAL  # max constituent severity
    assert r0.score == 95  # 90 + 5*(2-1)
    assert r0.entities == ("alice",)
    assert r0.dedup_key == "R0:alice"
    # time_range spans min start to max end; evidence = sorted alert_ids.
    assert r0.time_range == (_T0, _T1)
    assert r0.evidence == tuple(sorted(("R4-alice", "R2-alice")))


def test_separate_entities_not_merged() -> None:
    alerts = (
        _alert("R4", Severity.MEDIUM, 60, "alice", _T0, _T0),
        _alert("R2", Severity.CRITICAL, 90, "bob", _T1, _T1),
    )
    # Different entities, each with a single rule -> no R0.
    assert correlate(alerts, min_rules=2) == ()


def test_score_clamped_to_100() -> None:
    alerts = (
        _alert("R1", Severity.HIGH, 100, "x", _T0, _T0),
        _alert("R2", Severity.CRITICAL, 100, "x", _T0, _T0),
        _alert("R3", Severity.HIGH, 100, "x", _T0, _T0),
    )
    out = correlate(alerts, min_rules=2)
    assert out[0].score == 100  # 100 + 5*2 clamped

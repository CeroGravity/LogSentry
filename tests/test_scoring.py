"""Tests for scoring formulas and ranking."""

from __future__ import annotations

from datetime import UTC, datetime

from logsentry.models import Alert, Severity
from logsentry.scoring import rank_alerts, score_r1, score_r2


def test_score_r1_exact_values() -> None:
    # N=5. count=6,users=2 -> 70 + min(20, 5*((6-5)//5)=0) + min(10,2*1)=2 = 72.
    assert score_r1(count=6, distinct_users=2, min_failures=5) == 72
    # count=10,users=1 -> 70 + 5*((10-5)//5)=5 + 0 = 75.
    assert score_r1(count=10, distinct_users=1, min_failures=5) == 75
    # count=25,users=10 -> 70 + min(20, 5*4=20)=20 + min(10, 2*9=18)=10 = 100.
    assert score_r1(count=25, distinct_users=10, min_failures=5) == 100
    # clamp upper bound.
    assert score_r1(count=1000, distinct_users=50, min_failures=5) == 100


def test_score_r2_exact_values() -> None:
    # M=3. preceding=3 -> 90 + min(10, 2*0)=0 = 90.
    assert score_r2(preceding_failures=3, min_preceding_failures=3) == 90
    # preceding=6 -> 90 + min(10, 2*3=6)=6 = 96.
    assert score_r2(preceding_failures=6, min_preceding_failures=3) == 96
    # preceding=20 -> 90 + min(10, 2*17)=10 = 100.
    assert score_r2(preceding_failures=20, min_preceding_failures=3) == 100


def _alert(rule_id: str, sev: Severity, score: float, start: datetime,
           dedup: str) -> Alert:
    return Alert(
        alert_id="x",
        rule_id=rule_id,
        title="t",
        severity=sev,
        score=score,
        time_range=(start, start),
        entities=("e",),
        evidence=("ev",),
        description="d",
        dedup_key=dedup,
    )


def test_critical_outranks_high_regardless_of_score() -> None:
    # Severity is primary: a CRITICAL/90 must rank above a boosted HIGH/100.
    t0 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
    high100 = _alert("R3", Severity.HIGH, 100, t0, "high100")
    crit90 = _alert("R2", Severity.CRITICAL, 90, t0, "crit90")
    ranked = rank_alerts((high100, crit90))
    assert [x.dedup_key for x in ranked] == ["crit90", "high100"]


def test_rank_severity_then_score_then_tiebreaks() -> None:
    t0 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
    t1 = datetime(2026, 1, 1, 1, 0, 0, tzinfo=UTC)
    crit = _alert("R2", Severity.CRITICAL, 90, t1, "crit")  # severity-primary
    a = _alert("R1", Severity.HIGH, 72, t1, "a")            # HIGH, later start
    c = _alert("R1", Severity.HIGH, 72, t0, "c")            # HIGH, earlier start
    hi_score = _alert("R3", Severity.HIGH, 80, t1, "hi")    # HIGH, higher score
    ranked = rank_alerts((a, hi_score, crit, c))
    # CRITICAL first; then within HIGH: higher score (hi=80) before 72s;
    # the 72 tie resolves by earlier start: c before a.
    assert [x.dedup_key for x in ranked] == ["crit", "hi", "c", "a"]

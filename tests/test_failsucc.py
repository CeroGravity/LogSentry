"""Tests for R2 failed_then_success."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from logsentry.config import (
    Allowlists,
    Config,
    R2FailedThenSuccess,
    load_config,
)
from logsentry.detectors import FailedThenSuccessDetector
from logsentry.geo import NullResolver
from logsentry.models import AuthMethod, LoginEvent, Outcome, Severity
from logsentry.parsers import AuthLogParser
from logsentry.protocols import AnalysisContext

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"

_NOW = datetime(2026, 1, 10, 20, 0, 0, tzinfo=UTC)
_BASE = datetime(2026, 1, 10, 13, 0, 0, tzinfo=UTC)


def _ctx(config: Config) -> AnalysisContext:
    return AnalysisContext(
        config=config,
        baseline_events=(),
        geo_resolver=NullResolver(),
        now=_NOW,
        tz=UTC,
    )


def _ev(i: int, user: str, ip: str, secs: int, outcome: Outcome) -> LoginEvent:
    return LoginEvent(
        event_id=f"e{i}",
        timestamp=_BASE + timedelta(seconds=secs),
        username=user,
        source_ip=ip,
        source_port=41000 + i,
        outcome=outcome,
        auth_method=AuthMethod.PASSWORD,
        hostname="h",
        raw=f"raw{i}",
        source_file="f.log",
        line_no=i,
    )


def test_positive_failures_then_success() -> None:
    cfg = Config(r2=R2FailedThenSuccess(window_seconds=300, min_preceding_failures=3))
    events = [
        _ev(1, "alice", "1.1.1.1", 0, Outcome.FAILURE),
        _ev(2, "alice", "1.1.1.1", 30, Outcome.FAILURE),
        _ev(3, "alice", "1.1.1.1", 60, Outcome.FAILURE),
        _ev(4, "alice", "1.1.1.1", 120, Outcome.SUCCESS),
    ]
    alerts = FailedThenSuccessDetector().analyze(events, _ctx(cfg))
    assert len(alerts) == 1
    a = alerts[0]
    assert a.severity is Severity.CRITICAL
    assert a.entities == ("alice", "1.1.1.1")
    # evidence = 3 failures + success, chronological.
    assert a.evidence == ("e1", "e2", "e3", "e4")
    assert a.dedup_key.endswith("e4")


def test_threshold_negative_too_few_failures() -> None:
    cfg = Config(r2=R2FailedThenSuccess(window_seconds=300, min_preceding_failures=3))
    events = [
        _ev(1, "alice", "1.1.1.1", 0, Outcome.FAILURE),
        _ev(2, "alice", "1.1.1.1", 30, Outcome.FAILURE),
        _ev(3, "alice", "1.1.1.1", 120, Outcome.SUCCESS),  # only 2 preceding
    ]
    assert FailedThenSuccessDetector().analyze(events, _ctx(cfg)) == []


def test_window_negative_failures_outside_window() -> None:
    cfg = Config(r2=R2FailedThenSuccess(window_seconds=300, min_preceding_failures=3))
    events = [
        _ev(1, "alice", "1.1.1.1", 0, Outcome.FAILURE),
        _ev(2, "alice", "1.1.1.1", 30, Outcome.FAILURE),
        _ev(3, "alice", "1.1.1.1", 60, Outcome.FAILURE),
        _ev(4, "alice", "1.1.1.1", 600, Outcome.SUCCESS),  # >300s after all
    ]
    assert FailedThenSuccessDetector().analyze(events, _ctx(cfg)) == []


def test_require_same_source_ip() -> None:
    # 3 failures from .1 then success from .2; same-ip required -> no alert.
    cfg = Config(
        r2=R2FailedThenSuccess(
            window_seconds=300, min_preceding_failures=3, require_same_source_ip=True
        )
    )
    events = [
        _ev(1, "alice", "1.1.1.1", 0, Outcome.FAILURE),
        _ev(2, "alice", "1.1.1.1", 30, Outcome.FAILURE),
        _ev(3, "alice", "1.1.1.1", 60, Outcome.FAILURE),
        _ev(4, "alice", "2.2.2.2", 120, Outcome.SUCCESS),
    ]
    assert FailedThenSuccessDetector().analyze(events, _ctx(cfg)) == []
    # Same scenario but require_same_source_ip=False -> alert fires.
    cfg2 = Config(
        r2=R2FailedThenSuccess(
            window_seconds=300, min_preceding_failures=3, require_same_source_ip=False
        )
    )
    assert len(FailedThenSuccessDetector().analyze(events, _ctx(cfg2))) == 1


def test_allowlisted_user_skipped() -> None:
    cfg = Config(
        r2=R2FailedThenSuccess(window_seconds=300, min_preceding_failures=3),
        allowlists=Allowlists(users=("alice",)),
    )
    events = [
        _ev(1, "alice", "1.1.1.1", 0, Outcome.FAILURE),
        _ev(2, "alice", "1.1.1.1", 30, Outcome.FAILURE),
        _ev(3, "alice", "1.1.1.1", 60, Outcome.FAILURE),
        _ev(4, "alice", "1.1.1.1", 120, Outcome.SUCCESS),
    ]
    assert FailedThenSuccessDetector().analyze(events, _ctx(cfg)) == []


def test_fixture_failsucc_log_positive_and_negative() -> None:
    cfg = load_config(FIXTURES / "analyze.toml")
    result = AuthLogParser(cfg).parse(FIXTURES / "failsucc.log")
    alerts = FailedThenSuccessDetector().analyze(list(result.events), _ctx(cfg))
    # alice positive; carol's success is >300s after her failures -> negative.
    assert len(alerts) == 1
    assert alerts[0].entities == ("alice", "192.0.2.5")

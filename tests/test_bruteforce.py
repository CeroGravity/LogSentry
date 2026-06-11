"""Tests for R1 brute_force_burst."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, tzinfo
from pathlib import Path

from logsentry.config import Allowlists, Config, R1BruteForce
from logsentry.detectors import BruteForceDetector
from logsentry.geo import NullResolver
from logsentry.models import AuthMethod, LoginEvent, Outcome, Severity
from logsentry.protocols import AnalysisContext

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"

_NOW = datetime(2026, 1, 10, 20, 0, 0, tzinfo=UTC)


def _ctx(config: Config) -> AnalysisContext:
    tz: tzinfo = UTC
    return AnalysisContext(
        config=config,
        baseline_events=(),
        geo_resolver=NullResolver(),
        now=_NOW,
        tz=tz,
    )


_BASE = datetime(2026, 1, 10, 13, 0, 0, tzinfo=UTC)


def _fail(i: int, ip: str, user: str, secs: int) -> LoginEvent:
    return LoginEvent(
        event_id=f"e{i}",
        timestamp=_BASE + timedelta(seconds=secs),
        username=user,
        source_ip=ip,
        source_port=40000 + i,
        outcome=Outcome.FAILURE,
        auth_method=AuthMethod.PASSWORD,
        hostname="h",
        raw=f"raw{i}",
        source_file="f.log",
        line_no=i,
    )


def test_single_burst_one_alert_with_correct_fields() -> None:
    cfg = Config(r1=R1BruteForce(window_seconds=60, min_failures=5))
    events = [_fail(i, "10.0.0.1", "root" if i % 2 else "admin", i * 5)
              for i in range(6)]
    alerts = BruteForceDetector().analyze(events, _ctx(cfg))
    assert len(alerts) == 1
    a = alerts[0]
    assert a.severity is Severity.HIGH
    assert a.rule_id == "R1"
    # count = 6 events; distinct users admin/root.
    assert a.entities == ("admin", "root", "10.0.0.1")
    assert len(a.evidence) == 6
    assert a.time_range == (events[0].timestamp, events[5].timestamp)


def test_sub_threshold_cluster_no_alert() -> None:
    cfg = Config(r1=R1BruteForce(window_seconds=60, min_failures=5))
    events = [_fail(i, "10.0.0.2", "bob", i * 5) for i in range(4)]  # only 4
    assert BruteForceDetector().analyze(events, _ctx(cfg)) == []


def test_window_splits_into_separate_bursts() -> None:
    cfg = Config(r1=R1BruteForce(window_seconds=60, min_failures=5))
    # First burst: 5 within 60s. Then a >60s gap, then another 5 within 60s.
    first = [_fail(i, "10.0.0.3", "x", i * 10) for i in range(5)]  # 0..40s
    second = [_fail(10 + i, "10.0.0.3", "x", 200 + i * 10) for i in range(5)]
    alerts = BruteForceDetector().analyze(first + second, _ctx(cfg))
    assert len(alerts) == 2


def test_per_user_keying() -> None:
    cfg = Config(r1=R1BruteForce(window_seconds=60, min_failures=5, per_user=True))
    # 5 for root + 5 for admin from same IP -> two bursts (per user).
    root = [_fail(i, "10.0.0.4", "root", i * 5) for i in range(5)]
    admin = [_fail(10 + i, "10.0.0.4", "admin", i * 5) for i in range(5)]
    alerts = BruteForceDetector().analyze(root + admin, _ctx(cfg))
    assert len(alerts) == 2
    # Without per_user, the combined 10 would be a single burst.
    cfg2 = Config(r1=R1BruteForce(window_seconds=60, min_failures=5))
    assert len(BruteForceDetector().analyze(root + admin, _ctx(cfg2))) == 1


def test_allowlisted_ip_skipped() -> None:
    cfg = Config(
        r1=R1BruteForce(window_seconds=60, min_failures=5),
        allowlists=Allowlists(ips=("10.0.0.5",)),
    )
    events = [_fail(i, "10.0.0.5", "root", i * 5) for i in range(8)]
    assert BruteForceDetector().analyze(events, _ctx(cfg)) == []


def test_fixture_burst_log_single_alert() -> None:
    from logsentry.config import load_config
    from logsentry.parsers import AuthLogParser

    cfg = load_config(FIXTURES / "analyze.toml")
    result = AuthLogParser(cfg).parse(FIXTURES / "burst.log")
    alerts = BruteForceDetector().analyze(list(result.events), _ctx(cfg))
    assert len(alerts) == 1
    assert alerts[0].entities == ("admin", "root", "198.51.100.23")

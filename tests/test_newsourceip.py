"""Tests for R5 new_source_ip_per_user."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from logsentry.config import Config, R5NewSourceIP
from logsentry.detectors import NewSourceIPDetector
from logsentry.geo import NullResolver
from logsentry.models import AuthMethod, LoginEvent, Outcome, Severity
from logsentry.protocols import AnalysisContext
from logsentry.scoring import score_r5

_NOW = datetime(2026, 1, 10, 20, 0, 0, tzinfo=UTC)
_BASE = datetime(2026, 1, 10, 13, 0, 0, tzinfo=UTC)


def _ctx(config: Config, baseline: tuple[LoginEvent, ...]) -> AnalysisContext:
    return AnalysisContext(
        config=config,
        baseline_events=baseline,
        geo_resolver=NullResolver(),
        now=_NOW,
        tz=UTC,
    )


def _ev(i: int, user: str, ip: str, outcome: Outcome = Outcome.SUCCESS) -> LoginEvent:
    return LoginEvent(
        event_id=f"e{i}",
        timestamp=_BASE + timedelta(seconds=i),
        username=user,
        source_ip=ip,
        source_port=22,
        outcome=outcome,
        auth_method=AuthMethod.PASSWORD,
        hostname="h",
        raw=f"raw{i}",
        source_file="f.log",
        line_no=i,
    )


def test_new_ip_alerts_once() -> None:
    cfg = Config(r5=R5NewSourceIP())
    baseline = (_ev(1, "alice", "1.1.1.1"),)
    events = [
        _ev(2, "alice", "1.1.1.1"),   # known -> no alert
        _ev(3, "alice", "2.2.2.2"),   # new -> alert
        _ev(4, "alice", "2.2.2.2"),   # repeat -> no alert
    ]
    alerts = NewSourceIPDetector().analyze(events, _ctx(cfg, baseline))
    assert len(alerts) == 1
    a = alerts[0]
    assert a.severity is Severity.LOW
    assert a.entities == ("alice", "2.2.2.2")
    assert a.dedup_key == "R5:alice:2.2.2.2"
    assert a.details is not None
    assert a.details.known_ip_count == 1  # type: ignore[union-attr]


def test_empty_baseline_user_is_silent() -> None:
    cfg = Config(r5=R5NewSourceIP())
    # No baseline for 'newbie' -> learn silently, never alert.
    events = [_ev(1, "newbie", "9.9.9.9"), _ev(2, "newbie", "8.8.8.8")]
    assert NewSourceIPDetector().analyze(events, _ctx(cfg, ())) == []


def test_only_success_ignores_failures() -> None:
    cfg = Config(r5=R5NewSourceIP(only_success=True))
    baseline = (_ev(1, "alice", "1.1.1.1"),)
    # New IP but on a FAILURE -> ignored by default.
    events = [_ev(2, "alice", "2.2.2.2", Outcome.FAILURE)]
    assert NewSourceIPDetector().analyze(events, _ctx(cfg, baseline)) == []
    # With only_success=false the failure participates.
    cfg2 = Config(r5=R5NewSourceIP(only_success=False))
    base2 = (_ev(1, "alice", "1.1.1.1"),)
    alerts = NewSourceIPDetector().analyze(events, _ctx(cfg2, base2))
    assert len(alerts) == 1


def test_baseline_included_ip_not_realerted() -> None:
    cfg = Config(r5=R5NewSourceIP())
    baseline = (_ev(1, "alice", "1.1.1.1"),)
    # The same event re-appearing in analyzed input is already known.
    events = [_ev(1, "alice", "1.1.1.1")]
    assert NewSourceIPDetector().analyze(events, _ctx(cfg, baseline)) == []


def test_score_r5_flat() -> None:
    assert score_r5() == 30


def test_fixture_file_baseline(tmp_path: Path) -> None:
    from logsentry.config import load_config
    from logsentry.engine import build_stream
    from logsentry.parsers import AuthLogParser

    root = Path(__file__).resolve().parents[1]
    fixtures = root / "tests" / "fixtures"
    cfg = load_config(fixtures / "newip.toml")
    base_res = AuthLogParser(cfg).parse(Path("tests/fixtures/newip_baseline.log"))
    win_res = AuthLogParser(cfg).parse(Path("tests/fixtures/newip_window.log"))
    base_events, _ = build_stream([base_res])
    events, _ = build_stream([win_res])
    alerts = NewSourceIPDetector().analyze(list(events), _ctx(cfg, base_events))
    assert len(alerts) == 1
    assert alerts[0].entities == ("alice", "203.0.113.200")

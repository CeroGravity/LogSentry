"""Tests for R4 off_hours_access."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from logsentry.config import Config, R4OffHours
from logsentry.detectors import OffHoursDetector
from logsentry.geo import NullResolver
from logsentry.models import AuthMethod, LoginEvent, Outcome, Severity
from logsentry.protocols import AnalysisContext
from logsentry.scoring import score_r4

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"

_NOW = datetime(2026, 1, 10, 20, 0, 0, tzinfo=UTC)


def _ctx(config: Config) -> AnalysisContext:
    return AnalysisContext(
        config=config,
        baseline_events=(),
        geo_resolver=NullResolver(),
        now=_NOW,
        tz=UTC,
    )


def _cfg() -> Config:
    return Config(r4=R4OffHours(timezone="America/New_York"))


def _ev(ts: datetime, user: str, outcome: Outcome = Outcome.SUCCESS) -> LoginEvent:
    return LoginEvent(
        event_id=f"e-{user}-{ts.isoformat()}",
        timestamp=ts,
        username=user,
        source_ip="8.8.8.8",
        source_port=22,
        outcome=outcome,
        auth_method=AuthMethod.PASSWORD,
        hostname="h",
        raw="raw",
        source_file="f.log",
        line_no=1,
    )


def test_in_hours_weekday_no_alert() -> None:
    # Tue 2026-01-13 10:00 ET = 15:00 UTC -> in business hours.
    ev = _ev(datetime(2026, 1, 13, 15, 0, tzinfo=UTC), "alice")
    assert OffHoursDetector().analyze([ev], _ctx(_cfg())) == []


def test_weekday_evening_alert_score_50() -> None:
    # Tue 2026-01-13 20:00 ET = 2026-01-14 01:00 UTC -> outside window.
    ev = _ev(datetime(2026, 1, 14, 1, 0, tzinfo=UTC), "bob")
    alerts = OffHoursDetector().analyze([ev], _ctx(_cfg()))
    assert len(alerts) == 1
    assert alerts[0].severity is Severity.MEDIUM
    assert alerts[0].score == 50
    assert alerts[0].details is not None
    assert alerts[0].details.non_business_day is False  # type: ignore[union-attr]
    assert alerts[0].details.weekday == "Tuesday"  # type: ignore[union-attr]


def test_weekend_alert_score_60() -> None:
    # Sat 2026-01-10 12:00 ET = 17:00 UTC -> non-business day.
    ev = _ev(datetime(2026, 1, 10, 17, 0, tzinfo=UTC), "carol")
    alerts = OffHoursDetector().analyze([ev], _ctx(_cfg()))
    assert len(alerts) == 1
    assert alerts[0].score == 60
    assert alerts[0].details.non_business_day is True  # type: ignore[union-attr]
    assert alerts[0].details.weekday == "Saturday"  # type: ignore[union-attr]


def test_only_success_ignores_failures() -> None:
    # A failed login at an off-hours time is ignored by default.
    ev = _ev(datetime(2026, 1, 14, 2, 0, tzinfo=UTC), "dave", Outcome.FAILURE)
    assert OffHoursDetector().analyze([ev], _ctx(_cfg())) == []


def test_score_r4_formula() -> None:
    assert score_r4(non_business_day=False) == 50
    assert score_r4(non_business_day=True) == 60


def test_fixture_offhours_log() -> None:
    from logsentry.config import load_config
    from logsentry.parsers import AuthLogParser

    cfg = load_config(FIXTURES / "offhours.toml")
    result = AuthLogParser(cfg).parse(Path("tests/fixtures/offhours.log"))
    alerts = OffHoursDetector().analyze(list(result.events), _ctx(cfg))
    # bob (evening, 50) + carol (weekend, 60); alice in-hours, dave failed.
    # Different users/dates -> still 2 single-event alerts, unchanged.
    scores = sorted(a.score for a in alerts)
    assert scores == [50, 60]
    assert all(a.details.event_count == 1 for a in alerts)  # type: ignore[union-attr]


def test_collapse_same_user_same_date_one_alert() -> None:
    from logsentry.config import load_config
    from logsentry.parsers import AuthLogParser

    cfg = load_config(FIXTURES / "offhours.toml")
    result = AuthLogParser(cfg).parse(Path("tests/fixtures/offhours_collapse.log"))
    alerts = OffHoursDetector().analyze(list(result.events), _ctx(cfg))
    # frank: 3 off-hours logins on 2026-01-10 collapse to one; 2026-01-12 separate.
    assert len(alerts) == 2
    by_date = {a.dedup_key: a for a in alerts}
    sat = by_date["R4:frank:2026-01-10"]
    assert sat.details.event_count == 3  # type: ignore[union-attr]
    assert len(sat.evidence) == 3
    assert sat.score == 60  # Saturday, non-business day
    assert "(3 logins)" in sat.description
    assert sat.details.last_local_time != sat.details.local_time  # type: ignore[union-attr]
    mon = by_date["R4:frank:2026-01-12"]
    assert mon.details.event_count == 1  # type: ignore[union-attr]
    assert mon.score == 50  # Monday evening
    assert "logins)" not in mon.description  # single-event wording unchanged


def test_collapsed_time_range_spans_first_to_last() -> None:
    cfg = _cfg()
    # Two off-hours events same user/date (Saturday).
    e1 = _ev(datetime(2026, 1, 10, 17, 0, tzinfo=UTC), "grace")
    e2 = _ev(datetime(2026, 1, 10, 23, 0, tzinfo=UTC), "grace")
    alerts = OffHoursDetector().analyze([e1, e2], _ctx(cfg))
    assert len(alerts) == 1
    assert alerts[0].time_range == (e1.timestamp, e2.timestamp)
    assert alerts[0].evidence == (e1.event_id, e2.event_id)

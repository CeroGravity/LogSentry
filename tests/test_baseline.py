"""Tests for R5 baseline derivation modes (engine.derive_baseline)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from logsentry.engine import derive_baseline
from logsentry.models import AuthMethod, LoginEvent, Outcome

_BASE = datetime(2026, 1, 10, 13, 0, 0, tzinfo=UTC)


def _ev(i: int, secs: int) -> LoginEvent:
    return LoginEvent(
        event_id=f"e{i}",
        timestamp=_BASE + timedelta(seconds=secs),
        username="alice",
        source_ip=f"1.1.1.{i}",
        source_port=22,
        outcome=Outcome.SUCCESS,
        auth_method=AuthMethod.PASSWORD,
        hostname="h",
        raw=f"raw{i}",
        source_file="f.log",
        line_no=i,
    )


def _stream() -> tuple[LoginEvent, ...]:
    return tuple(_ev(i, i * 10) for i in range(1, 11))  # 10 events, 0..90s


def test_unset_baseline_is_empty() -> None:
    assert derive_baseline(_stream(), None) == ()
    assert derive_baseline(_stream(), "") == ()


def test_cutoff_ts_splits_by_time() -> None:
    events = _stream()
    # Cutoff at +35s -> events at 10,20,30s (e1..e3) are baseline.
    cutoff = (_BASE + timedelta(seconds=35)).isoformat()
    base = derive_baseline(events, f"cutoff_ts:{cutoff}")
    assert [e.event_id for e in base] == ["e1", "e2", "e3"]


def test_first_n_percent_splits_by_count() -> None:
    events = _stream()
    # 30% of 10 = 3 events (first by ts, line_no).
    base = derive_baseline(events, "first_n_percent:30")
    assert [e.event_id for e in base] == ["e1", "e2", "e3"]


def test_first_n_percent_100_is_all() -> None:
    events = _stream()
    assert len(derive_baseline(events, "first_n_percent:100")) == 10


def test_bare_path_not_derived_in_stream() -> None:
    # A bare path is handled by the CLI, not derive_baseline -> empty here.
    assert derive_baseline(_stream(), "some/baseline.log") == ()

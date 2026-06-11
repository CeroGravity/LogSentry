"""Tests for the data model and deterministic ID helpers."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

import pytest

from logsentry.ids import alert_id, event_id
from logsentry.models import (
    Alert,
    AuthMethod,
    GeoLocation,
    LoginEvent,
    Outcome,
    Severity,
)


def _sample_event() -> LoginEvent:
    ts = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
    eid = event_id("auth.log", 42, "raw line")
    return LoginEvent(
        event_id=eid,
        timestamp=ts,
        username="alice",
        source_ip="203.0.113.7",
        source_port=51514,
        outcome=Outcome.FAILURE,
        auth_method=AuthMethod.PASSWORD,
        hostname="host1",
        raw="raw line",
        source_file="auth.log",
        line_no=42,
    )


def test_login_event_constructs_with_expected_fields() -> None:
    ev = _sample_event()
    assert ev.username == "alice"
    assert ev.outcome is Outcome.FAILURE
    assert ev.timestamp.tzinfo is UTC


def test_login_event_is_frozen() -> None:
    ev = _sample_event()
    with pytest.raises(FrozenInstanceError):
        ev.username = "bob"  # type: ignore[misc]


def test_geo_location_constructs() -> None:
    loc = GeoLocation(
        ip="203.0.113.7",
        lat=1.0,
        lon=2.0,
        country="US",
        city="Nowhere",
        source="static",
        is_private=False,
    )
    assert loc.is_private is False
    assert loc.country == "US"


def test_alert_constructs_and_severity_orders() -> None:
    start = datetime(2024, 1, 1, 12, 0, tzinfo=UTC)
    end = datetime(2024, 1, 1, 12, 5, tzinfo=UTC)
    alert = Alert(
        alert_id="x",
        rule_id="R1",
        title="burst",
        severity=Severity.HIGH,
        score=8.0,
        time_range=(start, end),
        entities=("203.0.113.7",),
        evidence=("e1",),
        description="desc",
        dedup_key="R1:203.0.113.7",
    )
    assert alert.rule_id == "R1"
    assert Severity.INFO.value < Severity.CRITICAL.value


def test_event_id_is_deterministic() -> None:
    a = event_id("auth.log", 1, "same raw")
    b = event_id("auth.log", 1, "same raw")
    assert a == b


def test_event_id_changes_with_input() -> None:
    base = event_id("auth.log", 1, "raw")
    assert event_id("auth.log", 2, "raw") != base
    assert event_id("other.log", 1, "raw") != base
    assert event_id("auth.log", 1, "raw2") != base


def test_event_id_field_boundaries_do_not_collide() -> None:
    # "a|bc" vs "ab|c" must not hash equal due to naive concatenation.
    assert event_id("a", 0, "bc") != event_id("ab", 0, "c")


def test_alert_id_is_deterministic() -> None:
    args = ("R1", "R1:1.2.3.4", ("2024-01-01T00:00:00", "2024-01-01T00:01:00"),
            ("1.2.3.4",))
    assert alert_id(*args) == alert_id(*args)

"""Allowlists suppress uniformly across R3, R4, R5."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

from logsentry.config import Allowlists, Config, R4OffHours, R5NewSourceIP
from logsentry.detectors import (
    ImpossibleTravelDetector,
    NewSourceIPDetector,
    OffHoursDetector,
)
from logsentry.geo import NullResolver
from logsentry.models import AuthMethod, GeoLocation, LoginEvent, Outcome
from logsentry.protocols import AnalysisContext, GeoResolver

_NOW = datetime(2026, 1, 10, 20, 0, 0, tzinfo=UTC)
_BASE = datetime(2026, 1, 10, 13, 0, 0, tzinfo=UTC)

_COORDS = {"7.0.0.1": (40.7128, -74.0060), "7.0.0.2": (51.5074, -0.1278)}


class _DictResolver:
    def resolve(self, ip: str) -> GeoLocation | None:
        if ip in _COORDS:
            lat, lon = _COORDS[ip]
            return GeoLocation(ip, lat, lon, "XX", "c", "test", False)
        return None


def _ctx(config: Config, resolver: GeoResolver,
         baseline: tuple[LoginEvent, ...] = ()) -> AnalysisContext:
    return AnalysisContext(
        config=config, baseline_events=baseline,
        geo_resolver=resolver, now=_NOW, tz=UTC,
    )


def _ev(i: int, user: str, ip: str, secs: int) -> LoginEvent:
    return LoginEvent(
        event_id=f"e{i}", timestamp=_BASE + timedelta(seconds=secs),
        username=user, source_ip=ip, source_port=22,
        outcome=Outcome.SUCCESS, auth_method=AuthMethod.PASSWORD,
        hostname="h", raw=f"raw{i}", source_file="f.log", line_no=i,
    )


def test_r3_suppressed_by_allowlisted_user() -> None:
    cfg = Config(allowlists=Allowlists(users=("svc",)))
    events = [_ev(1, "svc", "7.0.0.1", 0), _ev(2, "svc", "7.0.0.2", 1800)]
    assert ImpossibleTravelDetector().analyze(events, _ctx(cfg, _DictResolver())) == []


def test_r3_suppressed_by_allowlisted_ip() -> None:
    cfg = Config(allowlists=Allowlists(ips=("7.0.0.2",)))
    events = [_ev(1, "alice", "7.0.0.1", 0), _ev(2, "alice", "7.0.0.2", 1800)]
    # The London endpoint is allowlisted -> that event is dropped -> no pair.
    assert ImpossibleTravelDetector().analyze(events, _ctx(cfg, _DictResolver())) == []


def test_r4_suppressed_by_allowlist() -> None:
    # Saturday login (off-hours) but user is allowlisted.
    cfg = Config(
        r4=R4OffHours(timezone="UTC"),
        allowlists=Allowlists(users=("svc",)),
    )
    sat = datetime(2026, 1, 10, 12, 0, tzinfo=UTC)  # Saturday
    ev = replace(_ev(1, "svc", "8.8.8.8", 0), timestamp=sat)
    assert OffHoursDetector().analyze([ev], _ctx(cfg, NullResolver())) == []


def test_r5_suppressed_by_allowlisted_ip() -> None:
    cfg = Config(
        r5=R5NewSourceIP(),
        allowlists=Allowlists(ips=("2.2.2.2",)),
    )
    baseline = (_ev(1, "alice", "1.1.1.1", 0),)
    events = [_ev(2, "alice", "2.2.2.2", 1)]  # new IP but allowlisted
    ctx = _ctx(cfg, _DictResolver(), baseline)
    assert NewSourceIPDetector().analyze(events, ctx) == []

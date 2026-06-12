"""Tests for R3 impossible_travel."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from logsentry.config import Config, R3ImpossibleTravel
from logsentry.detectors import ImpossibleTravelDetector
from logsentry.geo import StaticResolver
from logsentry.models import (
    AuthMethod,
    GeoLocation,
    LoginEvent,
    Outcome,
    Severity,
)
from logsentry.protocols import AnalysisContext, GeoResolver

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"

_NOW = datetime(2026, 1, 10, 20, 0, 0, tzinfo=UTC)
_BASE = datetime(2026, 1, 10, 13, 0, 0, tzinfo=UTC)

# Minimal in-memory resolver keyed by IP.
_COORDS: dict[str, tuple[float, float]] = {
    "1.0.0.1": (40.7128, -74.0060),   # New York
    "1.0.0.2": (51.5074, -0.1278),    # London
    "1.0.0.3": (40.7129, -74.0061),   # ~NYC (tiny hop)
}


class _DictResolver:
    def resolve(self, ip: str) -> GeoLocation | None:
        if ip in _COORDS:
            lat, lon = _COORDS[ip]
            return GeoLocation(ip, lat, lon, "XX", "city", "test", False)
        return None  # unknown public IP


def _ctx(config: Config, resolver: GeoResolver) -> AnalysisContext:
    return AnalysisContext(
        config=config,
        baseline_events=(),
        geo_resolver=resolver,
        now=_NOW,
        tz=UTC,
    )


def _ev(i: int, user: str, ip: str, secs: int, outcome: Outcome) -> LoginEvent:
    return LoginEvent(
        event_id=f"e{i}",
        timestamp=_BASE + timedelta(seconds=secs),
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


def _cfg(**kw: object) -> Config:
    return Config(r3=R3ImpossibleTravel(**kw))  # type: ignore[arg-type]


def test_impossible_pair_one_alert() -> None:
    cfg = _cfg(max_kmh=900, min_distance_km=500)
    events = [
        _ev(1, "alice", "1.0.0.1", 0, Outcome.SUCCESS),
        _ev(2, "alice", "1.0.0.2", 1800, Outcome.SUCCESS),  # 30 min, ~5570 km
    ]
    alerts = ImpossibleTravelDetector().analyze(events, _ctx(cfg, _DictResolver()))
    assert len(alerts) == 1
    a = alerts[0]
    assert a.severity is Severity.HIGH
    assert a.entities == ("alice", "1.0.0.1", "1.0.0.2")
    assert a.evidence == ("e1", "e2")
    assert a.details is not None
    assert a.details.delta_seconds == 1800
    assert round(a.details.distance_km) == 5570
    assert a.details.implied_kmh > 900


def test_possible_travel_negative() -> None:
    cfg = _cfg(max_kmh=900, min_distance_km=500)
    # NYC -> London but 10 hours apart: ~557 km/h, below max_kmh.
    events = [
        _ev(1, "alice", "1.0.0.1", 0, Outcome.SUCCESS),
        _ev(2, "alice", "1.0.0.2", 36000, Outcome.SUCCESS),
    ]
    assert ImpossibleTravelDetector().analyze(events, _ctx(cfg, _DictResolver())) == []


def test_below_min_distance_negative() -> None:
    cfg = _cfg(max_kmh=900, min_distance_km=500)
    # Two near-identical NYC points 1 second apart: tiny distance < min_distance.
    events = [
        _ev(1, "alice", "1.0.0.1", 0, Outcome.SUCCESS),
        _ev(2, "alice", "1.0.0.3", 1, Outcome.SUCCESS),
    ]
    assert ImpossibleTravelDetector().analyze(events, _ctx(cfg, _DictResolver())) == []


def test_unresolved_or_private_endpoint_skipped() -> None:
    cfg = _cfg(max_kmh=900, min_distance_km=500)
    # Second IP is unknown to the resolver -> pair skipped, no alert/error.
    events = [
        _ev(1, "alice", "1.0.0.1", 0, Outcome.SUCCESS),
        _ev(2, "alice", "9.9.9.9", 1800, Outcome.SUCCESS),
    ]
    assert ImpossibleTravelDetector().analyze(events, _ctx(cfg, _DictResolver())) == []


def test_failures_ignored_unless_consider_failures() -> None:
    # A failure at London then a success at NYC; default ignores the failure.
    events = [
        _ev(1, "alice", "1.0.0.2", 0, Outcome.FAILURE),
        _ev(2, "alice", "1.0.0.1", 1800, Outcome.SUCCESS),
    ]
    det = ImpossibleTravelDetector()
    default = _cfg(max_kmh=900, min_distance_km=500, consider_failures=False)
    assert det.analyze(events, _ctx(default, _DictResolver())) == []
    # With consider_failures, the failure participates -> impossible pair alerts.
    considered = _cfg(max_kmh=900, min_distance_km=500, consider_failures=True)
    assert len(det.analyze(events, _ctx(considered, _DictResolver()))) == 1


def test_non_positive_delta_treated_impossible() -> None:
    cfg = _cfg(max_kmh=900, min_distance_km=500)
    # Same timestamp, different far-apart cities -> delta 0, distance > 0.
    e1 = _ev(1, "alice", "1.0.0.1", 0, Outcome.SUCCESS)
    e2 = _ev(2, "alice", "1.0.0.2", 0, Outcome.SUCCESS)
    alerts = ImpossibleTravelDetector().analyze([e1, e2], _ctx(cfg, _DictResolver()))
    assert len(alerts) == 1
    assert alerts[0].details is not None
    assert alerts[0].details.delta_seconds == 0


def test_sandwich_gap_unresolved_interior_event_does_not_break_pair() -> None:
    # NYC -> [private/unresolved IP] -> London inside an impossible window.
    # The interior unresolved event must be dropped, re-pairing NYC<->London.
    cfg = _cfg(max_kmh=900, min_distance_km=500)
    events = [
        _ev(1, "alice", "1.0.0.1", 0, Outcome.SUCCESS),        # NYC (resolved)
        _ev(2, "alice", "10.0.0.99", 900, Outcome.SUCCESS),    # private (unresolved)
        _ev(3, "alice", "1.0.0.2", 1800, Outcome.SUCCESS),     # London (resolved)
    ]
    alerts = ImpossibleTravelDetector().analyze(events, _ctx(cfg, _DictResolver()))
    assert len(alerts) == 1
    assert alerts[0].entities == ("alice", "1.0.0.1", "1.0.0.2")


def test_fixture_travel_log_single_alert() -> None:
    from logsentry.config import load_config
    from logsentry.geo import CachingResolver
    from logsentry.parsers import AuthLogParser

    cfg = load_config(FIXTURES / "travel.toml")
    result = AuthLogParser(cfg).parse(Path("tests/fixtures/travel.log"))
    resolver = CachingResolver(StaticResolver(FIXTURES / "geo_static.csv"))
    det = ImpossibleTravelDetector()
    alerts = det.analyze(list(result.events), _ctx(cfg, resolver))
    assert len(alerts) == 1
    assert alerts[0].entities == ("alice", "45.32.10.1", "51.15.20.2")


def test_fixture_sandwich_log_one_alert() -> None:
    from logsentry.config import load_config
    from logsentry.geo import CachingResolver
    from logsentry.parsers import AuthLogParser

    cfg = load_config(FIXTURES / "travel.toml")
    result = AuthLogParser(cfg).parse(Path("tests/fixtures/travel_sandwich.log"))
    resolver = CachingResolver(StaticResolver(FIXTURES / "geo_static.csv"))
    det = ImpossibleTravelDetector()
    alerts = det.analyze(list(result.events), _ctx(cfg, resolver))
    assert len(alerts) == 1
    assert alerts[0].entities == ("carol", "45.32.10.1", "51.15.20.2")

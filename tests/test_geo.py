"""Tests for geo resolvers and haversine."""

from __future__ import annotations

from pathlib import Path

import pytest

from logsentry.geo import (
    CachingResolver,
    MaxMindResolver,
    NullResolver,
    StaticResolver,
    haversine,
)
from logsentry.models import GeoLocation

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
STATIC_CSV = FIXTURES / "geo_static.csv"


def test_static_resolves_known_ip() -> None:
    r = StaticResolver(STATIC_CSV)
    loc = r.resolve("45.32.10.1")
    assert loc is not None
    assert (loc.lat, loc.lon) == (40.7128, -74.0060)
    assert loc.country == "US"
    assert loc.is_private is False


def test_static_unknown_public_ip_returns_none() -> None:
    r = StaticResolver(STATIC_CSV)
    assert r.resolve("8.8.4.4") is None


def test_private_ip_flagged_without_calling_inner() -> None:
    r = StaticResolver(STATIC_CSV)
    loc = r.resolve("10.0.0.5")
    assert loc is not None
    assert loc.is_private is True
    assert loc.lat is None and loc.lon is None


class _CountingResolver:
    """Inner resolver that counts how often resolve() is called per IP."""

    def __init__(self) -> None:
        self.calls: dict[str, int] = {}

    def resolve(self, ip: str) -> GeoLocation | None:
        self.calls[ip] = self.calls.get(ip, 0) + 1
        return GeoLocation(ip, 1.0, 2.0, "US", "X", "test", False)


def test_caching_calls_inner_once_per_ip() -> None:
    inner = _CountingResolver()
    cache = CachingResolver(inner)
    for _ in range(3):
        cache.resolve("1.1.1.1")
    cache.resolve("2.2.2.2")
    cache.resolve("1.1.1.1")
    assert inner.calls == {"1.1.1.1": 1, "2.2.2.2": 1}


def test_caching_preserves_none_results() -> None:
    r = CachingResolver(StaticResolver(STATIC_CSV))
    assert r.resolve("8.8.4.4") is None
    assert r.resolve("8.8.4.4") is None  # still None, served from cache


def test_null_resolver_public_none_private_flagged() -> None:
    r = NullResolver()
    assert r.resolve("8.8.8.8") is None
    loc = r.resolve("192.168.1.1")
    assert loc is not None and loc.is_private is True


def test_haversine_nyc_london_within_one_percent() -> None:
    km = haversine(40.7128, -74.0060, 51.5074, -0.1278)
    # NYC -> London is ~5570 km.
    assert abs(km - 5570) / 5570 < 0.01


def test_haversine_zero_for_same_point() -> None:
    assert haversine(10.0, 20.0, 10.0, 20.0) == pytest.approx(0.0)


def test_maxmind_missing_dependency_fails_loud(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # Simulate geoip2 being unavailable: import inside the resolver must raise
    # a clear RuntimeError rather than a bare ImportError.
    import builtins

    real_import = builtins.__import__

    def fake_import(name: str, *args: object, **kwargs: object):  # type: ignore[no-untyped-def]
        if name.startswith("geoip2"):
            raise ImportError("no geoip2")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(RuntimeError, match="geoip2"):
        MaxMindResolver("nonexistent.mmdb")

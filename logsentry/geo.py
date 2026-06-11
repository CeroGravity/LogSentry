"""Geo resolvers and great-circle distance.

Pluggable IP->location resolution behind the
:class:`~logsentry.protocols.GeoResolver` protocol:

- :class:`NullResolver` — resolves nothing.
- :class:`StaticResolver` — offline CSV map (deterministic; used by tests).
- :class:`MaxMindResolver` — reads a LOCAL GeoLite2 ``.mmdb`` only. The
  ``geoip2``/``maxminddb`` dependency is imported **lazily** so its absence
  never breaks the rest of the tool.
- :class:`CachingResolver` — memoizes any resolver, one inner call per IP.

No network anywhere: ``MaxMindResolver`` reads a local file; no DB download,
no online lookup.
"""

from __future__ import annotations

import csv
import ipaddress
import math
from pathlib import Path

from .models import GeoLocation


def haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in kilometres between two lat/lon points."""
    radius_km = 6371.0088
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lambda = math.radians(lon2 - lon1)
    a = (
        math.sin(d_phi / 2) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2) ** 2
    )
    return 2 * radius_km * math.asin(math.sqrt(a))


def _is_non_public(ip: str) -> bool:
    """True for private/reserved/loopback/link-local addresses (no public geo)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (
        addr.is_private
        or addr.is_reserved
        or addr.is_loopback
        or addr.is_link_local
    )


def _private_location(ip: str, source: str) -> GeoLocation:
    """A coordinate-less :class:`GeoLocation` flagged private."""
    return GeoLocation(
        ip=ip,
        lat=None,
        lon=None,
        country=None,
        city=None,
        source=source,
        is_private=True,
    )


class NullResolver:
    """A :class:`~logsentry.protocols.GeoResolver` that resolves nothing."""

    def resolve(self, ip: str) -> GeoLocation | None:
        """Return a private marker for non-public IPs, else ``None``."""
        if _is_non_public(ip):
            return _private_location(ip, "null")
        return None


class StaticResolver:
    """Resolve IPs from an offline CSV (``ip,lat,lon,country,city``).

    Deterministic and dependency-free. Unknown public IP -> ``None``.
    """

    def __init__(self, csv_path: str | Path) -> None:
        self._table: dict[str, GeoLocation] = {}
        with Path(csv_path).open("r", encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                ip = (row.get("ip") or "").strip()
                if not ip:
                    continue
                self._table[ip] = GeoLocation(
                    ip=ip,
                    lat=float(row["lat"]),
                    lon=float(row["lon"]),
                    country=(row.get("country") or "").strip() or None,
                    city=(row.get("city") or "").strip() or None,
                    source="static",
                    is_private=False,
                )

    def resolve(self, ip: str) -> GeoLocation | None:
        if _is_non_public(ip):
            return _private_location(ip, "static")
        return self._table.get(ip)


class MaxMindResolver:
    """Resolve IPs from a local GeoLite2 ``.mmdb`` (lazy ``geoip2`` import)."""

    def __init__(self, mmdb_path: str | Path) -> None:
        self._mmdb_path = str(mmdb_path)
        self._reader = self._open_reader(self._mmdb_path)

    @staticmethod
    def _open_reader(path: str) -> object:
        """Open the local mmdb, importing ``geoip2`` lazily.

        Raises ``RuntimeError`` with an install hint if the dependency is
        absent. No network: this reads a local file only.
        """
        try:
            import geoip2.database  # type: ignore[import-not-found]  # noqa: PLC0415
        except ImportError as exc:
            raise RuntimeError(
                "MaxMindResolver requires the 'geoip2' package "
                "(pip install geoip2); it is an optional dependency."
            ) from exc
        return geoip2.database.Reader(path)

    def resolve(self, ip: str) -> GeoLocation | None:
        if _is_non_public(ip):
            return _private_location(ip, "maxmind")
        # geoip2 was imported in __init__; reuse the open reader.
        import geoip2.errors  # type: ignore[import-not-found]  # noqa: PLC0415

        try:
            response = self._reader.city(ip)  # type: ignore[attr-defined]
        except geoip2.errors.AddressNotFoundError:
            return None
        lat = response.location.latitude
        lon = response.location.longitude
        return GeoLocation(
            ip=ip,
            lat=lat,
            lon=lon,
            country=response.country.iso_code,
            city=response.city.name,
            source="maxmind",
            is_private=False,
        )


class CachingResolver:
    """Memoize an inner resolver: at most one ``inner.resolve`` per unique IP."""

    def __init__(self, inner: object) -> None:
        self._inner = inner
        self._cache: dict[str, GeoLocation | None] = {}

    def resolve(self, ip: str) -> GeoLocation | None:
        if ip in self._cache:
            return self._cache[ip]
        result: GeoLocation | None = self._inner.resolve(ip)  # type: ignore[attr-defined]
        self._cache[ip] = result
        return result

"""Core data model for LogSentry.

Frozen dataclasses and enums only. No detection, parsing, or I/O logic.
All timestamps are timezone-aware UTC by contract (enforced by parsers in
later phases, documented here).
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from datetime import datetime


class Outcome(enum.Enum):
    """Result of an authentication attempt."""

    SUCCESS = "success"
    FAILURE = "failure"
    INVALID_USER = "invalid_user"


class AuthMethod(enum.Enum):
    """Authentication method used for an attempt."""

    PASSWORD = "password"
    PUBLICKEY = "publickey"
    OTHER = "other"
    UNKNOWN = "unknown"


class Severity(enum.Enum):
    """Alert severity, ordered from least to most urgent.

    Backed by an integer so severities sort deterministically.
    """

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass(frozen=True)
class LoginEvent:
    """A single authentication event parsed from a log source.

    ``timestamp`` must be timezone-aware UTC. ``raw`` preserves the original
    source line for evidence and reproducibility.
    """

    event_id: str
    timestamp: datetime
    username: str | None
    source_ip: str | None
    source_port: int | None
    outcome: Outcome
    auth_method: AuthMethod
    hostname: str | None
    raw: str
    source_file: str
    line_no: int


@dataclass(frozen=True)
class GeoLocation:
    """Geographic location for an IP address.

    Populated by a :class:`~logsentry.protocols.GeoResolver`. ``is_private``
    flags RFC 1918 / loopback / link-local addresses that have no public geo.
    """

    ip: str
    lat: float | None
    lon: float | None
    country: str | None
    city: str | None
    source: str
    is_private: bool


@dataclass(frozen=True)
class GeoPoint:
    """A single geo-located endpoint (one side of a travel pair)."""

    ip: str
    lat: float | None
    lon: float | None
    country: str | None
    city: str | None


@dataclass(frozen=True)
class GeoDetail:
    """Structured detail for an impossible-travel (R3) alert.

    ``distance_km`` is great-circle km; ``delta_seconds`` is the elapsed time
    between the two events; ``implied_kmh`` is the implied travel speed.
    """

    src: GeoPoint
    dst: GeoPoint
    distance_km: float
    delta_seconds: int
    implied_kmh: int


@dataclass(frozen=True)
class OffHoursDetail:
    """Structured detail for an off-hours-access (R4) alert."""

    local_time: str        # ISO local time in the configured timezone
    weekday: str           # e.g. "Saturday"
    business_window: str   # e.g. "Mon-Fri 08:00-18:00 America/New_York"
    non_business_day: bool


@dataclass(frozen=True)
class NewSourceIPDetail:
    """Structured detail for a new-source-IP (R5) alert."""

    new_ip: str
    known_ip_count: int    # size of the user's baseline known-set


# Rule-specific structured detail attached to an alert.
AlertDetail = GeoDetail | OffHoursDetail | NewSourceIPDetail


@dataclass(frozen=True)
class Alert:
    """A ranked anomaly finding produced by a detector.

    ``dedup_key`` collapses semantically duplicate alerts; ``alert_id`` is a
    deterministic identity derived from canonical fields (see
    :mod:`logsentry.ids`). ``details`` is additive and rule-specific (R3 uses
    :class:`GeoDetail`); it defaults to ``None`` so existing rules are
    unchanged.
    """

    alert_id: str
    rule_id: str
    title: str
    severity: Severity
    score: float
    time_range: tuple[datetime, datetime]
    entities: tuple[str, ...]
    evidence: tuple[str, ...]
    description: str
    dedup_key: str
    details: AlertDetail | None = None

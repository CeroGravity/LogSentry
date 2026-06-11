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
class Alert:
    """A ranked anomaly finding produced by a detector.

    ``dedup_key`` collapses semantically duplicate alerts; ``alert_id`` is a
    deterministic identity derived from canonical fields (see
    :mod:`logsentry.ids`).
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

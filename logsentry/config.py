"""Configuration model and loader for LogSentry.

Frozen dataclasses with per-rule sections and documented defaults, plus a
``tomllib`` loader and value-range validation. No detection logic —
configuration shape only.

The only I/O permitted here is reading a local TOML file. No network access.
Detectors and parsers may assume the loaded config has been validated.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field, fields
from datetime import time
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .models import Severity


def _parse_hhmm(value: str) -> time:
    """Parse an ``HH:MM`` 24-hour string into a :class:`datetime.time`."""
    hh, _, mm = value.partition(":")
    return time(hour=int(hh), minute=int(mm))


@dataclass(frozen=True)
class R1BruteForce:
    """R1 brute_force_burst thresholds."""

    window_seconds: int = 60
    min_failures: int = 10
    per_user: bool = False


@dataclass(frozen=True)
class R2FailedThenSuccess:
    """R2 failed_then_success thresholds."""

    window_seconds: int = 300
    min_preceding_failures: int = 5
    require_same_source_ip: bool = True


@dataclass(frozen=True)
class R3ImpossibleTravel:
    """R3 impossible_travel thresholds."""

    max_kmh: int = 900
    min_distance_km: int = 500
    consider_failures: bool = False


@dataclass(frozen=True)
class R4OffHours:
    """R4 off_hours_access window.

    ``timezone`` is required (no default) — off-hours is meaningless without
    an explicit timezone, in line with the determinism mandate.
    """

    timezone: str
    business_days: tuple[int, ...] = (0, 1, 2, 3, 4)  # Mon–Fri (Mon=0)
    business_start: time = field(default_factory=lambda: time(8, 0))
    business_end: time = field(default_factory=lambda: time(18, 0))
    only_success: bool = True


@dataclass(frozen=True)
class R5NewSourceIP:
    """R5 new_source_ip_per_user settings."""

    baseline_source: str | None = None
    only_success: bool = True


@dataclass(frozen=True)
class Allowlists:
    """Entities excluded from alerting."""

    ips: tuple[str, ...] = ()
    users: tuple[str, ...] = ()


# Default CSV column names (logical field -> column header).
_DEFAULT_CSV_COLUMNS: dict[str, str] = {
    "timestamp": "timestamp",
    "username": "username",
    "source_ip": "source_ip",
    "source_port": "source_port",
    "outcome": "outcome",
    "auth_method": "auth_method",
    "hostname": "hostname",
}


@dataclass(frozen=True)
class CsvConfig:
    """CSV ingestion mapping.

    ``columns`` maps each logical field to its CSV header name.
    ``outcome_map`` / ``auth_method_map`` translate CSV cell strings to the
    enum *names* (e.g. ``"SUCCESS"``, ``"PASSWORD"``). ``timestamp_format`` is
    an ``strptime`` pattern; if a parsed timestamp is naive,
    ``ingest.log_timezone`` is applied.
    """

    columns: dict[str, str] = field(
        default_factory=lambda: dict(_DEFAULT_CSV_COLUMNS)
    )
    outcome_map: dict[str, str] = field(default_factory=dict)
    auth_method_map: dict[str, str] = field(default_factory=dict)
    timestamp_format: str = "%Y-%m-%dT%H:%M:%S%z"


@dataclass(frozen=True)
class Ingest:
    """Ingestion settings shared across parsers.

    ``log_timezone`` (IANA name) is required: syslog and naive CSV timestamps
    carry no zone, so one must be supplied explicitly (determinism mandate).
    ``log_year`` pins the year for year-less syslog timestamps; it is required
    when parsing such lines (their absence raises a clear error — no
    file-metadata inference). Not needed for ISO8601 logs or CSV input.
    """

    log_timezone: str
    log_year: int | None = None
    csv: CsvConfig = field(default_factory=CsvConfig)


@dataclass(frozen=True)
class Output:
    """Output / exit-code settings.

    ``fail_severity`` is the lowest severity (by name) at which the CLI exits
    non-zero (exit 1) when at least one alert reaches it.
    """

    fail_severity: str = "HIGH"


@dataclass(frozen=True)
class Config:
    """Top-level LogSentry configuration."""

    r1: R1BruteForce = field(default_factory=R1BruteForce)
    r2: R2FailedThenSuccess = field(default_factory=R2FailedThenSuccess)
    r3: R3ImpossibleTravel = field(default_factory=R3ImpossibleTravel)
    r4: R4OffHours = field(default_factory=lambda: R4OffHours(timezone="UTC"))
    r5: R5NewSourceIP = field(default_factory=R5NewSourceIP)
    allowlists: Allowlists = field(default_factory=Allowlists)
    ingest: Ingest = field(default_factory=lambda: Ingest(log_timezone="UTC"))
    output: Output = field(default_factory=Output)


def _coerce_section(cls: type[Any], data: dict[str, Any]) -> Any:
    """Build a frozen-dataclass section from a TOML table.

    Unknown keys raise loudly. ``time`` fields accept ``HH:MM`` strings and
    sequence fields are coerced to tuples for immutability.
    """
    valid = {f.name: f for f in fields(cls)}
    unknown = set(data) - set(valid)
    if unknown:
        raise ValueError(
            f"{cls.__name__}: unknown config keys: {sorted(unknown)}"
        )
    kwargs: dict[str, Any] = {}
    for key, value in data.items():
        # ``f.type`` is a string here (PEP 563 deferred annotations); compare
        # by name rather than identity.
        ftype = str(valid[key].type)
        if ftype == "time":
            kwargs[key] = _parse_hhmm(value)
        elif isinstance(value, list):
            kwargs[key] = tuple(value)
        else:
            kwargs[key] = value
    return cls(**kwargs)


def _build_ingest(data: dict[str, Any]) -> Ingest:
    """Build the :class:`Ingest` section, handling the nested ``csv`` table."""
    valid = {"log_timezone", "log_year", "csv"}
    unknown = set(data) - valid
    if unknown:
        raise ValueError(f"ingest: unknown config keys: {sorted(unknown)}")
    csv = _coerce_section(CsvConfig, data["csv"]) if "csv" in data else None
    if "log_timezone" not in data:
        raise ValueError("ingest: 'log_timezone' is required")
    kwargs: dict[str, Any] = {"log_timezone": data["log_timezone"]}
    if "log_year" in data:
        kwargs["log_year"] = data["log_year"]
    if csv is not None:
        kwargs["csv"] = csv
    return Ingest(**kwargs)


def load_config(path: str | Path) -> Config:
    """Load and validate a :class:`Config` from a TOML file on disk.

    Missing sections fall back to documented defaults. Reading a local file is
    the only I/O performed; no network access occurs. The returned config is
    range- and timezone-validated; callers may assume it is well-formed.
    """
    raw = Path(path).read_bytes()
    data = tomllib.loads(raw.decode("utf-8"))
    config = _config_from_dict(data)
    validate_config(config)
    return config


def _config_from_dict(data: dict[str, Any]) -> Config:
    """Construct a :class:`Config` from a parsed TOML mapping."""
    section_types: dict[str, type[Any]] = {
        "r1": R1BruteForce,
        "r2": R2FailedThenSuccess,
        "r3": R3ImpossibleTravel,
        "r4": R4OffHours,
        "r5": R5NewSourceIP,
        "allowlists": Allowlists,
        "output": Output,
    }
    kwargs: dict[str, Any] = {}
    for name, cls in section_types.items():
        if name in data:
            kwargs[name] = _coerce_section(cls, data[name])
    if "ingest" in data:
        kwargs["ingest"] = _build_ingest(data["ingest"])
    return Config(**kwargs)


def _require_tz(name: str, value: str) -> None:
    """Raise ``ValueError`` if ``value`` is not a resolvable IANA timezone."""
    try:
        ZoneInfo(value)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError(f"{name}: unknown timezone {value!r}") from exc


def validate_config(config: Config) -> None:
    """Validate value ranges and timezones; raise ``ValueError`` on any issue.

    Fail-loud, so detectors and parsers can assume a pre-validated config.
    """
    r1, r2, r3, r4 = config.r1, config.r2, config.r3, config.r4
    if r1.window_seconds < 0:
        raise ValueError("r1.window_seconds must be >= 0")
    if r1.min_failures < 0:
        raise ValueError("r1.min_failures must be >= 0")
    if r2.window_seconds < 0:
        raise ValueError("r2.window_seconds must be >= 0")
    if r2.min_preceding_failures < 1:
        raise ValueError("r2.min_preceding_failures must be >= 1")
    if r3.max_kmh <= 0:
        raise ValueError("r3.max_kmh must be > 0")
    if r3.min_distance_km < 0:
        raise ValueError("r3.min_distance_km must be >= 0")
    if r4.business_start >= r4.business_end:
        raise ValueError("r4.business_start must be < r4.business_end")
    _require_tz("r4.timezone", r4.timezone)
    _require_tz("ingest.log_timezone", config.ingest.log_timezone)
    valid_sev = {s.name for s in Severity}
    if config.output.fail_severity not in valid_sev:
        raise ValueError(
            f"output.fail_severity must be one of {sorted(valid_sev)}"
        )

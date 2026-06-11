"""Tests for config value-range and timezone validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from logsentry.config import Config, R1BruteForce, load_config, validate_config

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "cfg.toml"
    p.write_text(body, encoding="utf-8")
    return p


def test_good_config_validates() -> None:
    cfg = load_config(FIXTURES / "ingest.toml")
    assert isinstance(cfg, Config)
    assert cfg.ingest.log_timezone == "America/New_York"
    assert cfg.ingest.log_year == 2026


def test_example_toml_validates() -> None:
    cfg = load_config(ROOT / "logsentry.example.toml")
    assert cfg.ingest.log_timezone == "UTC"


def test_negative_window_rejected() -> None:
    cfg = Config(r1=R1BruteForce(window_seconds=-1))
    with pytest.raises(ValueError, match="r1.window_seconds"):
        validate_config(cfg)


def test_r2_min_preceding_failures_must_be_at_least_one(tmp_path: Path) -> None:
    body = '[ingest]\nlog_timezone = "UTC"\n[r2]\nmin_preceding_failures = 0\n'
    with pytest.raises(ValueError, match="min_preceding_failures"):
        load_config(_write(tmp_path, body))


def test_r3_max_kmh_must_be_positive(tmp_path: Path) -> None:
    body = '[ingest]\nlog_timezone = "UTC"\n[r3]\nmax_kmh = 0\n'
    with pytest.raises(ValueError, match="max_kmh"):
        load_config(_write(tmp_path, body))


def test_r4_business_hours_order(tmp_path: Path) -> None:
    body = (
        '[ingest]\nlog_timezone = "UTC"\n'
        '[r4]\ntimezone = "UTC"\n'
        'business_start = "18:00"\nbusiness_end = "08:00"\n'
    )
    with pytest.raises(ValueError, match="business_start"):
        load_config(_write(tmp_path, body))


def test_bad_r4_timezone_rejected(tmp_path: Path) -> None:
    body = '[ingest]\nlog_timezone = "UTC"\n[r4]\ntimezone = "Mars/Phobos"\n'
    with pytest.raises(ValueError, match="timezone"):
        load_config(_write(tmp_path, body))


def test_bad_ingest_timezone_rejected(tmp_path: Path) -> None:
    body = '[ingest]\nlog_timezone = "Not/AZone"\n'
    with pytest.raises(ValueError, match="ingest.log_timezone"):
        load_config(_write(tmp_path, body))


def test_ingest_log_timezone_required(tmp_path: Path) -> None:
    body = "[ingest]\nlog_year = 2026\n"
    with pytest.raises(ValueError, match="log_timezone"):
        load_config(_write(tmp_path, body))

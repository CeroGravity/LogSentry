"""Tests for configuration defaults and TOML loading."""

from __future__ import annotations

from datetime import time
from pathlib import Path

import pytest

from logsentry.config import Config, load_config

EXAMPLE_TOML = Path(__file__).resolve().parents[1] / "logsentry.example.toml"


def test_defaults_match_spec() -> None:
    cfg = Config()
    assert cfg.r1.window_seconds == 60
    assert cfg.r1.min_failures == 10
    assert cfg.r1.per_user is False
    assert cfg.r2.window_seconds == 300
    assert cfg.r2.min_preceding_failures == 5
    assert cfg.r2.require_same_source_ip is True
    assert cfg.r3.max_kmh == 900
    assert cfg.r3.min_distance_km == 500
    assert cfg.r3.consider_failures is False
    assert cfg.r4.business_days == (0, 1, 2, 3, 4)
    assert cfg.r4.business_start == time(8, 0)
    assert cfg.r4.business_end == time(18, 0)
    assert cfg.r4.only_success is True
    assert cfg.r5.only_success is True
    assert cfg.allowlists.ips == ()
    assert cfg.allowlists.users == ()


def test_example_toml_parses() -> None:
    cfg = load_config(EXAMPLE_TOML)
    assert isinstance(cfg, Config)
    assert cfg.r4.timezone  # required key is present in the example
    assert cfg.r1.min_failures >= 1


def test_example_toml_time_fields_parsed() -> None:
    cfg = load_config(EXAMPLE_TOML)
    assert isinstance(cfg.r4.business_start, time)
    assert isinstance(cfg.r4.business_end, time)


def test_unknown_key_fails_loudly(tmp_path: Path) -> None:
    bad = tmp_path / "bad.toml"
    bad.write_text("[r1]\nbogus_key = 1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unknown config keys"):
        load_config(bad)

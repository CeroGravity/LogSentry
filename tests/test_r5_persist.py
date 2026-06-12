"""Tests for opt-in persistent R5 baseline state."""

from __future__ import annotations

import json
from pathlib import Path

from logsentry.cli import main
from logsentry.state import load_state, save_state

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
NOW = "2026-01-10T20:00:00+00:00"


def _persist_config(tmp_path: Path, state_file: Path) -> Path:
    cfg = tmp_path / "persist.toml"
    cfg.write_text(
        "[r5]\n"
        "only_success = true\n"
        "persist = true\n"
        f'state_path = "{state_file}"\n'
        '[ingest]\nlog_timezone = "UTC"\n'
        # Neutralize R4 so the run's only alerts are R5.
        '[r4]\ntimezone = "UTC"\nbusiness_days = [0,1,2,3,4,5,6]\n'
        'business_start = "00:00"\nbusiness_end = "23:59"\n',
        encoding="utf-8",
    )
    return cfg


def _run(cfg: Path, log: Path, out: Path, baseline: Path | None = None) -> int:
    argv = ["analyze", str(log), "--config", str(cfg), "--now", NOW,
            "--format", "json", "--output", str(out)]
    if baseline is not None:
        argv += ["--baseline", str(baseline)]
    return main(argv)


def test_run1_writes_sorted_state_then_run2_suppresses(tmp_path: Path) -> None:
    state_file = tmp_path / "r5_state.json"
    cfg = _persist_config(tmp_path, state_file)
    out1 = tmp_path / "r1.json"

    # Run 1: baseline seeds alice's known IPs; the new IP raises one R5 alert.
    code1 = _run(cfg, FIXTURES / "newip_window.log", out1,
                 baseline=FIXTURES / "newip_baseline.log")
    assert code1 in (0, 1)
    report1 = json.loads(out1.read_text(encoding="utf-8"))
    r5_run1 = [a for a in report1["alerts"] if a["rule_id"] == "R5"]
    assert len(r5_run1) == 1  # alice's 203.0.113.200 is new

    # State file written, deterministic + sorted; now knows alice's new IP.
    assert state_file.is_file()
    state = json.loads(state_file.read_text(encoding="utf-8"))
    assert state["alice"] == sorted(state["alice"])
    assert "203.0.113.200" in state["alice"]

    # Run 2: same input, now seeded from persisted state -> no new R5 alert.
    out2 = tmp_path / "r2.json"
    _run(cfg, FIXTURES / "newip_window.log", out2,
         baseline=FIXTURES / "newip_baseline.log")
    report2 = json.loads(out2.read_text(encoding="utf-8"))
    r5_run2 = [a for a in report2["alerts"] if a["rule_id"] == "R5"]
    assert r5_run2 == []  # previously-new IP is now persisted/known


def test_state_roundtrip_is_sorted_and_atomic_named(tmp_path: Path) -> None:
    path = tmp_path / "s.json"
    save_state(path, {"bob": {"2.2.2.2", "1.1.1.1"}, "ann": {"9.9.9.9"}})
    text = path.read_text(encoding="utf-8")
    # sort_keys + sorted IP lists -> deterministic content.
    data = json.loads(text)
    assert list(data.keys()) == ["ann", "bob"]
    assert data["bob"] == ["1.1.1.1", "2.2.2.2"]
    assert load_state(path) == {"bob": {"1.1.1.1", "2.2.2.2"}, "ann": {"9.9.9.9"}}


def test_missing_state_file_loads_empty(tmp_path: Path) -> None:
    assert load_state(tmp_path / "nope.json") == {}

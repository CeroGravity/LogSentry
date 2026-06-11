"""Tests for CLI exit codes 0 / 1 / 2."""

from __future__ import annotations

from pathlib import Path

from logsentry.cli import main

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
CONFIG = str(FIXTURES / "analyze.toml")
NOW = "2026-01-10T20:00:00+00:00"


def test_exit_1_when_high_alert(capsys) -> None:  # type: ignore[no-untyped-def]
    code = main([
        "analyze", str(FIXTURES / "burst.log"),
        "--config", CONFIG, "--now", NOW, "--format", "json",
    ])
    capsys.readouterr()
    assert code == 1


def test_exit_0_when_no_qualifying_alert(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    # A log with only a couple of failures: below R1 threshold, no success.
    log = tmp_path / "quiet.log"
    log.write_text(
        "2026-01-10T13:00:00+00:00 h sshd[1]: "
        "Failed password for u from 9.9.9.9 port 1 ssh2\n"
        "2026-01-10T13:00:05+00:00 h sshd[2]: "
        "Failed password for u from 9.9.9.9 port 2 ssh2\n",
        encoding="utf-8",
    )
    code = main([
        "analyze", str(log), "--config", CONFIG, "--now", NOW, "--format", "json",
    ])
    capsys.readouterr()
    assert code == 0


def test_exit_2_on_fatal_parse_error(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    # CSV missing the required 'outcome' column -> fatal parse error.
    bad = tmp_path / "bad.csv"
    bad.write_text(
        "timestamp,username,source_ip\n"
        "2026-01-10T13:00:00+0000,alice,1.2.3.4\n",
        encoding="utf-8",
    )
    code = main([
        "analyze", str(bad), "--config", CONFIG, "--now", NOW,
        "--input-type", "csv",
    ])
    capsys.readouterr()
    assert code == 2


def test_exit_2_on_missing_input(capsys) -> None:  # type: ignore[no-untyped-def]
    code = main([
        "analyze", "does_not_exist.log", "--config", CONFIG, "--now", NOW,
    ])
    capsys.readouterr()
    assert code == 2


def test_exit_2_on_bad_now(capsys) -> None:  # type: ignore[no-untyped-def]
    code = main([
        "analyze", str(FIXTURES / "burst.log"), "--config", CONFIG,
        "--now", "not-a-timestamp",
    ])
    capsys.readouterr()
    assert code == 2

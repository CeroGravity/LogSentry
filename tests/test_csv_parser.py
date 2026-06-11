"""Tests for the CSV login-event parser."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from logsentry.config import load_config
from logsentry.models import AuthMethod, Outcome
from logsentry.parsers import CsvParser

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"


def _parser() -> CsvParser:
    config = load_config(FIXTURES / "ingest.toml")
    return CsvParser(config)


def test_clean_csv_maps_columns_to_events() -> None:
    result = _parser().parse(FIXTURES / "events_clean.csv")
    assert result.errors == ()
    assert len(result.events) == 4
    first = result.events[0]
    assert first.username == "alice"
    assert first.outcome is Outcome.SUCCESS
    assert first.auth_method is AuthMethod.PASSWORD
    assert first.source_ip == "203.0.113.7"
    assert first.source_port == 51514
    assert first.timestamp == datetime(2026, 1, 10, 13, 55, 36, tzinfo=UTC)
    assert first.timestamp.tzinfo is UTC


def test_outcome_and_method_mapping() -> None:
    result = _parser().parse(FIXTURES / "events_clean.csv")
    outcomes = [e.outcome for e in result.events]
    assert outcomes == [
        Outcome.SUCCESS,
        Outcome.FAILURE,
        Outcome.INVALID_USER,
        Outcome.SUCCESS,
    ]
    assert result.events[3].auth_method is AuthMethod.PUBLICKEY
    assert result.events[3].source_ip == "2001:db8::1"


def test_missing_required_column_is_fatal_no_crash() -> None:
    result = _parser().parse(FIXTURES / "events_missing_col.csv")
    assert result.events == ()
    assert len(result.errors) == 1
    err = result.errors[0]
    assert err.fatal is True
    assert "outcome" in err.reason


def test_bad_rows_collected_and_counts_correct() -> None:
    result = _parser().parse(FIXTURES / "events_bad.csv")
    # Good rows: alice (line 2), zoe (line 6). Bad: bad ts (3), bad outcome (4),
    # unmapped method (5), short row (7).
    assert len(result.events) == 2
    assert [e.username for e in result.events] == ["alice", "zoe"]
    assert all(not e.fatal for e in result.errors)
    reasons = " | ".join(e.reason for e in result.errors)
    assert "timestamp" in reasons
    assert "outcome" in reasons
    assert "auth_method" in reasons
    assert "too few fields" in reasons
    assert len(result.errors) == 4


def test_order_preserved_and_event_id_deterministic() -> None:
    a = _parser().parse(FIXTURES / "events_clean.csv")
    b = _parser().parse(FIXTURES / "events_clean.csv")
    assert [e.event_id for e in a.events] == [e.event_id for e in b.events]
    assert [e.line_no for e in a.events] == [2, 3, 4, 5]

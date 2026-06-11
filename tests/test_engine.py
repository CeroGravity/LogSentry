"""Tests for the engine: merge, stable sort, error aggregation."""

from __future__ import annotations

from datetime import UTC, datetime

from logsentry.engine import build_stream
from logsentry.models import AuthMethod, LoginEvent, Outcome
from logsentry.parsers.base import ParseError, ParseResult


def _ev(ts: datetime, source_file: str, line_no: int, eid: str) -> LoginEvent:
    return LoginEvent(
        event_id=eid,
        timestamp=ts,
        username="u",
        source_ip="1.2.3.4",
        source_port=22,
        outcome=Outcome.FAILURE,
        auth_method=AuthMethod.PASSWORD,
        hostname="h",
        raw="raw",
        source_file=source_file,
        line_no=line_no,
    )


def test_merge_stable_sort_by_ts_file_line_id() -> None:
    t1 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
    t2 = datetime(2026, 1, 1, 0, 0, 1, tzinfo=UTC)
    r_a = ParseResult(
        events=(_ev(t2, "a.log", 5, "id2"), _ev(t1, "a.log", 1, "id1")),
        errors=(),
        source_file="a.log",
    )
    r_b = ParseResult(
        events=(_ev(t1, "b.log", 2, "id3"),),
        errors=(),
        source_file="b.log",
    )
    events, errors = build_stream([r_a, r_b])
    # Same ts t1: a.log:1 before b.log:2 (source_file tiebreak). Then t2 a.log:5.
    assert [e.event_id for e in events] == ["id1", "id3", "id2"]
    assert errors == ()


def test_error_aggregation_ordered_by_file_then_line() -> None:
    r_b = ParseResult(
        events=(),
        errors=(ParseError(9, "x", "late"), ParseError(2, "y", "early")),
        source_file="b.log",
    )
    r_a = ParseResult(
        events=(),
        errors=(ParseError(4, "z", "amid"),),
        source_file="a.log",
    )
    _events, errors = build_stream([r_b, r_a])
    # Ordered by (source_file, line_no): a.log:4, b.log:2, b.log:9.
    assert [(e.reason) for e in errors] == ["amid", "early", "late"]

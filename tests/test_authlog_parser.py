"""Tests for the sshd auth.log parser."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from logsentry.config import Config, Ingest, load_config
from logsentry.models import AuthMethod, Outcome
from logsentry.parsers import AuthLogParser

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"


def _parser() -> AuthLogParser:
    # ingest.toml: tz=America/New_York, log_year=2026.
    config = load_config(FIXTURES / "ingest.toml")
    return AuthLogParser(config)


def _parser_no_year() -> AuthLogParser:
    # No log_year configured: year-less syslog must raise a config error.
    config = Config(ingest=Ingest(log_timezone="America/New_York"))
    return AuthLogParser(config)


def test_syslog_classification_and_dedup() -> None:
    result = _parser().parse(FIXTURES / "auth_syslog.log")
    # Events only from the 3 sshd patterns: accepted password, failed password,
    # failed invalid user, accepted publickey, accepted keyboard-interactive,
    # failed publickey (hostname-as-ip). pam_unix / Invalid user / Connection
    # closed / non-syslog line must NOT produce events.
    outcomes = [(e.outcome, e.auth_method, e.username) for e in result.events]
    assert outcomes == [
        (Outcome.SUCCESS, AuthMethod.PASSWORD, "alice"),
        (Outcome.FAILURE, AuthMethod.PASSWORD, "bob"),
        (Outcome.INVALID_USER, AuthMethod.PASSWORD, "oracle"),
        (Outcome.SUCCESS, AuthMethod.PUBLICKEY, "carol"),
        (Outcome.SUCCESS, AuthMethod.OTHER, "dave"),
        (Outcome.FAILURE, AuthMethod.PUBLICKEY, "erin"),
    ]


def test_pam_unix_and_invalid_user_precursor_emit_no_events() -> None:
    result = _parser().parse(FIXTURES / "auth_syslog.log")
    raws = "\n".join(e.raw for e in result.events)
    assert "pam_unix" not in raws
    # The standalone "Invalid user oracle ... port 40224" precursor (no
    # "Failed") must not appear as its own event.
    assert "Invalid user oracle from 198.51.100.23 port 40224" not in raws


def test_malformed_auth_line_recorded_as_nonfatal_error() -> None:
    result = _parser().parse(FIXTURES / "auth_syslog.log")
    # "Failed password for from ... port" looks like an auth line but the
    # fields don't parse -> one non-fatal error.
    assert len(result.errors) == 1
    err = result.errors[0]
    assert err.fatal is False
    assert "malformed" in err.reason


def test_syslog_timestamp_converted_to_utc() -> None:
    result = _parser().parse(FIXTURES / "auth_syslog.log")
    # Jan 10 13:55:36 in America/New_York (EST, -05:00) -> 18:55:36 UTC.
    assert result.events[0].timestamp == datetime(2026, 1, 10, 18, 55, 36, tzinfo=UTC)
    assert result.events[0].timestamp.tzinfo is UTC


def test_yearless_syslog_without_log_year_raises() -> None:
    with pytest.raises(ValueError, match="year-less syslog requires ingest.log_year"):
        _parser_no_year().parse(FIXTURES / "auth_syslog.log")


def test_iso_unaffected_by_missing_log_year() -> None:
    # ISO lines carry their own year; parsing must succeed without log_year.
    result = _parser_no_year().parse(FIXTURES / "auth_iso.log")
    assert len(result.events) == 4
    assert result.events[0].timestamp == datetime(2026, 1, 10, 13, 55, 36, tzinfo=UTC)


def test_iso_timestamps_converted_to_utc() -> None:
    result = _parser().parse(FIXTURES / "auth_iso.log")
    ts = [e.timestamp for e in result.events]
    # +00:00, -05:00 (08:55:36-05 = 13:55:36Z), Z, and fractional all -> UTC.
    assert ts[0] == datetime(2026, 1, 10, 13, 55, 36, tzinfo=UTC)
    assert ts[1] == datetime(2026, 1, 10, 13, 55, 36, tzinfo=UTC)
    assert ts[2] == datetime(2026, 1, 10, 13, 55, 36, tzinfo=UTC)
    assert all(t.tzinfo is UTC for t in ts)


def test_ip_normalized_and_hostname_kept_verbatim() -> None:
    result = _parser().parse(FIXTURES / "auth_syslog.log")
    by_user = {e.username: e for e in result.events}
    # IPv6 compressed form.
    assert by_user["carol"].source_ip == "2001:db8::1"
    assert by_user["carol"].source_port == 50001
    # Non-IP token kept verbatim, not an error.
    assert by_user["erin"].source_ip == "resolved.example.com"


def test_event_id_deterministic_and_order_preserved() -> None:
    a = _parser().parse(FIXTURES / "auth_syslog.log")
    b = _parser().parse(FIXTURES / "auth_syslog.log")
    assert [e.event_id for e in a.events] == [e.event_id for e in b.events]
    # Order preserved: line numbers strictly increasing.
    line_nos = [e.line_no for e in a.events]
    assert line_nos == sorted(line_nos)

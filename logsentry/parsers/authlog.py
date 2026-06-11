"""Parser for Linux ``auth.log`` / sshd authentication lines.

Emits events from exactly three sshd line patterns (Accepted / Failed /
Failed ... invalid user). All other lines — including ``pam_unix(...)`` and
standalone ``Invalid user`` precursors — are ignored. Timestamps are converted
to UTC using an explicit configured timezone; the wall clock is never read.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from .. import ids
from ..config import Config
from ..models import AuthMethod, LoginEvent, Outcome
from .base import ParseError, ParseResult, normalize_ip, parse_port

# Traditional syslog prefix: "MMM DD HH:MM:SS host process[pid]: message"
# DD may be space-padded (" 5") in real syslog output.
_SYSLOG_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+\S+?(?:\[\d+\])?:\s+(?P<msg>.*)$"
)

# ISO8601 / RFC3339 prefix with offset: "2026-01-10T13:55:36+00:00 host proc: msg"
_ISO_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"(?:Z|[+-]\d{2}:?\d{2}))\s+"
    r"(?P<host>\S+)\s+\S+?(?:\[\d+\])?:\s+(?P<msg>.*)$"
)

# sshd auth messages. Order matters: the invalid-user variant must be tried
# before the plain Failed variant.
_ACCEPTED_RE = re.compile(
    r"^Accepted (?P<method>\S+) for (?P<user>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)"
)
_FAILED_INVALID_RE = re.compile(
    r"^Failed (?P<method>\S+) for invalid user (?P<user>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)"
)
_FAILED_RE = re.compile(
    r"^Failed (?P<method>\S+) for (?P<user>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)"
)

# A message that begins like an sshd auth event. Used only to decide whether a
# non-matching message is "malformed auth" (error) vs "not an auth line"
# (silently skipped). "Failed password ... for ..." with bad fields counts;
# "Failed none for ..." style precursors do too. The standalone "Invalid user"
# precursor is deliberately excluded so it is silently skipped.
_AUTH_PREFIX_RE = re.compile(r"^(Accepted|Failed)\s+\S+\s+for\b")

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _auth_method(token: str) -> AuthMethod:
    """Map an sshd method token to an :class:`AuthMethod`.

    ``password`` -> PASSWORD, ``publickey`` -> PUBLICKEY,
    ``keyboard-interactive`` (and its ``/pam`` forms) -> OTHER, else OTHER.
    """
    if token == "password":
        return AuthMethod.PASSWORD
    if token == "publickey":
        return AuthMethod.PUBLICKEY
    return AuthMethod.OTHER


class AuthLogParser:
    """Parse sshd auth lines from an ``auth.log`` file into ``LoginEvent``s."""

    def __init__(self, config: Config) -> None:
        self._config = config
        self._tz = ZoneInfo(config.ingest.log_timezone)

    def parse(self, path: Path) -> ParseResult:
        """Parse ``path``, preserving input order; never raises on bad lines.

        Raises ``ValueError`` only for the config/usage error of a year-less
        syslog line with no ``ingest.log_year`` configured (see ``_syslog_ts``).
        """
        source_file = str(path)
        # ``log_year`` may be None; year-less syslog lines then raise a clear
        # config error. No file-metadata inference — fully deterministic.
        year = self._config.ingest.log_year

        events: list[LoginEvent] = []
        errors: list[ParseError] = []
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line_no, raw_line in enumerate(fh, start=1):
                raw = raw_line.rstrip("\n")
                self._handle_line(
                    raw, line_no, year, source_file, events, errors
                )
        return ParseResult(
            events=tuple(events),
            errors=tuple(errors),
            source_file=source_file,
        )

    def _handle_line(
        self,
        raw: str,
        line_no: int,
        year: int | None,
        source_file: str,
        events: list[LoginEvent],
        errors: list[ParseError],
    ) -> None:
        """Process one line: extract ts + message, then classify the message."""
        parsed = self._split_line(raw, year)
        if parsed is None:
            # Not a recognized syslog/ISO line: silently skipped, not an error.
            return
        ts, host, msg = parsed
        match = self._match_auth(msg)
        if match is None:
            if _AUTH_PREFIX_RE.match(msg):
                # Looks like an sshd auth line ("Accepted"/"Failed ...") but
                # the field structure didn't parse: record as non-fatal.
                errors.append(
                    ParseError(
                        line_no=line_no,
                        raw=raw,
                        reason="malformed sshd auth line: fields did not parse",
                    )
                )
            # Otherwise not an auth line at all (pam_unix, standalone
            # "Invalid user", session lines): silently skipped, not an error.
            return
        outcome, method_token, user, ip, port = match
        events.append(
            LoginEvent(
                event_id=ids.event_id(source_file, line_no, raw),
                timestamp=ts,
                username=user,
                source_ip=normalize_ip(ip),
                source_port=parse_port(port),
                outcome=outcome,
                auth_method=_auth_method(method_token),
                hostname=host,
                raw=raw,
                source_file=source_file,
                line_no=line_no,
            )
        )

    def _split_line(
        self, raw: str, year: int | None
    ) -> tuple[datetime, str, str] | None:
        """Return (utc_ts, host, message) for a syslog/ISO line, else None.

        The ISO path carries its own year and ignores ``year``; the syslog
        path requires ``year`` (see ``_syslog_ts``).
        """
        iso = _ISO_RE.match(raw)
        if iso is not None:
            ts = datetime.fromisoformat(iso.group("ts"))
            return ts.astimezone(UTC), iso.group("host"), iso.group("msg")
        sys_m = _SYSLOG_RE.match(raw)
        if sys_m is not None:
            ts = self._syslog_ts(sys_m.group("ts"), year)
            return ts, sys_m.group("host"), sys_m.group("msg")
        return None

    def _syslog_ts(self, ts_str: str, year: int | None) -> datetime:
        """Convert a year-less syslog timestamp to UTC using configured tz.

        Year-less syslog timestamps have no year; ``ingest.log_year`` must be
        configured. Its absence is a config/usage error, not malformed data.
        """
        if year is None:
            raise ValueError(
                "year-less syslog requires ingest.log_year"
            )
        mon, day, clock = ts_str.split(maxsplit=2)
        hh, mm, ss = clock.split(":")
        local = datetime(
            year, _MONTHS[mon], int(day), int(hh), int(mm), int(ss),
            tzinfo=self._tz,
        )
        return local.astimezone(UTC)

    def _match_auth(
        self, msg: str
    ) -> tuple[Outcome, str, str, str, str] | None:
        """Classify an sshd message into (outcome, method, user, ip, port)."""
        m = _ACCEPTED_RE.match(msg)
        if m is not None:
            return (
                Outcome.SUCCESS, m.group("method"), m.group("user"),
                m.group("ip"), m.group("port"),
            )
        m = _FAILED_INVALID_RE.match(msg)
        if m is not None:
            return (
                Outcome.INVALID_USER, m.group("method"), m.group("user"),
                m.group("ip"), m.group("port"),
            )
        m = _FAILED_RE.match(msg)
        if m is not None:
            return (
                Outcome.FAILURE, m.group("method"), m.group("user"),
                m.group("ip"), m.group("port"),
            )
        return None

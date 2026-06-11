"""Parser for CSV login-event exports.

Header-based: configured column names map to logical fields. Required columns
are ``timestamp, username, source_ip, outcome``; a missing required column is a
fatal error. Bad rows are collected as non-fatal errors and parsing continues.
Timestamps are converted to UTC using an explicit configured timezone.
"""

from __future__ import annotations

import csv
from datetime import UTC, datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from .. import ids
from ..config import Config
from ..models import AuthMethod, LoginEvent, Outcome
from .base import ParseError, ParseResult, normalize_ip, parse_port

_REQUIRED_FIELDS = ("timestamp", "username", "source_ip", "outcome")


class CsvParser:
    """Parse a CSV of login events into ``LoginEvent``s."""

    def __init__(self, config: Config) -> None:
        self._config = config
        self._csv = config.ingest.csv
        self._tz = ZoneInfo(config.ingest.log_timezone)

    def parse(self, path: Path) -> ParseResult:
        """Parse ``path``; preserve row order; never raise on bad rows."""
        source_file = str(path)
        events: list[LoginEvent] = []
        errors: list[ParseError] = []

        with path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
            reader = csv.reader(fh)
            try:
                header = next(reader)
            except StopIteration:
                errors.append(
                    ParseError(1, "", "empty CSV file (no header row)", fatal=True)
                )
                return ParseResult((), tuple(errors), source_file)

            col_index = self._resolve_columns(header, errors)
            if col_index is None:
                return ParseResult((), tuple(errors), source_file)

            # Header is line 1; data rows start at line 2.
            for line_no, row in enumerate(reader, start=2):
                self._handle_row(
                    row, line_no, col_index, source_file, events, errors
                )

        return ParseResult(tuple(events), tuple(errors), source_file)

    def _resolve_columns(
        self, header: list[str], errors: list[ParseError]
    ) -> dict[str, int] | None:
        """Map logical fields to header indices, or fail loudly on a miss.

        Returns ``None`` (after recording a fatal error) if any required
        column is absent.
        """
        index_of = {name: i for i, name in enumerate(header)}
        col_index: dict[str, int] = {}
        for logical, column in self._csv.columns.items():
            if column in index_of:
                col_index[logical] = index_of[column]
        missing = [f for f in _REQUIRED_FIELDS if f not in col_index]
        if missing:
            errors.append(
                ParseError(
                    line_no=1,
                    raw=",".join(header),
                    reason=f"missing required column(s): {missing}",
                    fatal=True,
                )
            )
            return None
        return col_index

    def _handle_row(
        self,
        row: list[str],
        line_no: int,
        col_index: dict[str, int],
        source_file: str,
        events: list[LoginEvent],
        errors: list[ParseError],
    ) -> None:
        """Build a ``LoginEvent`` from one CSV row, or record a non-fatal error."""
        raw = ",".join(row)
        max_needed = max(col_index.values())
        if len(row) <= max_needed:
            errors.append(
                ParseError(line_no, raw, "row has too few fields")
            )
            return

        def cell(field: str) -> str | None:
            idx = col_index.get(field)
            if idx is None:
                return None
            value = row[idx].strip()
            return value or None

        ts_raw = cell("timestamp")
        if ts_raw is None:
            errors.append(ParseError(line_no, raw, "empty timestamp"))
            return
        ts = self._parse_timestamp(ts_raw)
        if ts is None:
            errors.append(
                ParseError(line_no, raw, f"unparseable timestamp: {ts_raw!r}")
            )
            return

        outcome = self._map_outcome(cell("outcome"))
        if outcome is None:
            errors.append(
                ParseError(
                    line_no, raw, f"unmapped outcome: {cell('outcome')!r}"
                )
            )
            return

        method = self._map_auth_method(cell("auth_method"))
        if method is None:
            errors.append(
                ParseError(
                    line_no, raw,
                    f"unmapped auth_method: {cell('auth_method')!r}",
                )
            )
            return

        ip_raw = cell("source_ip")
        events.append(
            LoginEvent(
                event_id=ids.event_id(source_file, line_no, raw),
                timestamp=ts,
                username=cell("username"),
                source_ip=normalize_ip(ip_raw) if ip_raw is not None else None,
                source_port=parse_port(cell("source_port")),
                outcome=outcome,
                auth_method=method,
                hostname=cell("hostname"),
                raw=raw,
                source_file=source_file,
                line_no=line_no,
            )
        )

    def _parse_timestamp(self, value: str) -> datetime | None:
        """Parse a timestamp per config format; apply tz if naive; -> UTC."""
        try:
            dt = datetime.strptime(value, self._csv.timestamp_format)
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=self._tz)
        return dt.astimezone(UTC)

    def _map_outcome(self, value: str | None) -> Outcome | None:
        """Map a CSV outcome cell to an :class:`Outcome` via config map."""
        if value is None:
            return None
        mapped = self._csv.outcome_map.get(value, value)
        try:
            return Outcome[mapped]
        except KeyError:
            return None

    def _map_auth_method(self, value: str | None) -> AuthMethod | None:
        """Map a CSV auth_method cell to an :class:`AuthMethod`.

        A missing/empty cell defaults to ``UNKNOWN`` (auth_method is optional).
        """
        if value is None:
            return AuthMethod.UNKNOWN
        mapped = self._csv.auth_method_map.get(value, value)
        try:
            return AuthMethod[mapped]
        except KeyError:
            return None

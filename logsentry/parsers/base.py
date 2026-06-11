"""Shared parser contracts and helpers.

Defines :class:`ParseError` / :class:`ParseResult` and small pure helpers used
by both parsers (IP normalization, port parsing). No I/O here.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from ..models import LoginEvent


@dataclass(frozen=True)
class ParseError:
    """A single problem encountered while parsing one input line/row.

    ``fatal`` marks an error that aborts the whole parse (e.g. a missing
    required CSV column); non-fatal errors are collected and parsing continues.
    """

    line_no: int
    raw: str
    reason: str
    fatal: bool = False


@dataclass(frozen=True)
class ParseResult:
    """Outcome of parsing one input file.

    ``events`` are in input order. ``errors`` collects every malformed
    line/row (non-fatal) plus any fatal error that aborted the parse.
    """

    events: tuple[LoginEvent, ...]
    errors: tuple[ParseError, ...]
    source_file: str


def normalize_ip(token: str) -> str:
    """Return the compressed canonical form of an IP address.

    If ``token`` is not a valid IPv4/IPv6 address (e.g. a resolved hostname),
    it is returned verbatim — this is not an error.
    """
    try:
        return ipaddress.ip_address(token).compressed
    except ValueError:
        return token


def parse_port(token: str | None) -> int | None:
    """Parse a port token to ``int``, or ``None`` if absent/non-numeric."""
    if token is None or token == "":
        return None
    try:
        return int(token)
    except ValueError:
        return None

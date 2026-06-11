"""Input parsers for LogSentry.

Turn raw input (Linux ``auth.log`` / sshd, or CSV) into normalized
:class:`~logsentry.models.LoginEvent` objects. Analysis only; the only I/O is
reading local input files. No network, no detection logic.
"""

from __future__ import annotations

from .authlog import AuthLogParser
from .base import ParseError, ParseResult
from .csvparser import CsvParser

__all__ = ["AuthLogParser", "CsvParser", "ParseError", "ParseResult"]

"""Command-line interface for LogSentry.

``analyze`` ingests inputs, runs the detector pipeline, and prints a
deterministic report. The only permitted wall-clock is ``generated_at``, taken
from ``--now`` (default: real UTC now). No network; only local file reads and
report output.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from . import __version__
from .config import Config, load_config
from .engine import build_detectors, build_stream, run_detectors
from .geo import NullResolver
from .models import Alert, Severity
from .parsers import AuthLogParser, CsvParser
from .parsers.base import ParseResult
from .protocols import AnalysisContext
from .report import render_json, render_text

_CSV_SUFFIXES = {".csv", ".tsv"}


class UsageError(Exception):
    """Raised for argument/usage problems that map to exit code 2."""


def build_parser() -> argparse.ArgumentParser:
    """Construct the top-level argument parser with the ``analyze`` command."""
    parser = argparse.ArgumentParser(
        prog="logsentry",
        description=(
            "LogSentry — defensive auth-log anomaly detector (blue-team only). "
            "Analysis only; no offensive capability."
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    sub = parser.add_subparsers(dest="command")

    analyze = sub.add_parser("analyze", help="Analyze auth logs / CSV input.")
    analyze.add_argument("inputs", nargs="+", help="Input file(s) to analyze.")
    analyze.add_argument("--config", type=str, default=None, help="Config TOML path.")
    analyze.add_argument(
        "--format", choices=("json", "text"), default="text",
        help="Output format (default: text).",
    )
    analyze.add_argument(
        "--input-type", choices=("auto", "auth", "csv"), default="auto",
        help="Input type; 'auto' detects by extension (default: auto).",
    )
    analyze.add_argument(
        "--timeline", action="store_true",
        help="Append a chronological event timeline (text format).",
    )
    analyze.add_argument(
        "--now", type=str, default=None,
        help="Injected ISO8601 clock for 'generated_at' (default: real UTC now).",
    )
    return parser


def _parse_now(value: str | None) -> datetime:
    """Resolve the injected clock; default is real UTC now (sole wall-clock)."""
    if value is None:
        return datetime.now(UTC)
    try:
        dt = datetime.fromisoformat(value)
    except ValueError as exc:
        raise UsageError(f"invalid --now value: {value!r}") from exc
    if dt.tzinfo is None:
        raise UsageError("--now must be timezone-aware (include an offset)")
    return dt.astimezone(UTC)


def _detect_type(path: Path, declared: str) -> str:
    if declared != "auto":
        return declared
    return "csv" if path.suffix.lower() in _CSV_SUFFIXES else "auth"


def _parse_inputs(
    inputs: Sequence[str], input_type: str, config: Config
) -> list[ParseResult]:
    """Parse every input file with the appropriate parser."""
    auth_parser = AuthLogParser(config)
    csv_parser = CsvParser(config)
    results: list[ParseResult] = []
    for raw_path in inputs:
        path = Path(raw_path)
        if not path.is_file():
            raise UsageError(f"input not found: {raw_path}")
        kind = _detect_type(path, input_type)
        parser = csv_parser if kind == "csv" else auth_parser
        results.append(parser.parse(path))
    return results


def _exit_code(
    alerts: Sequence[Alert], results: Sequence[ParseResult], config: Config
) -> int:
    """Compute exit code: 2 fatal-parse, 1 fail-severity reached, else 0."""
    if any(err.fatal for r in results for err in r.errors):
        return 2
    threshold = Severity[config.output.fail_severity].value
    if any(alert.severity.value >= threshold for alert in alerts):
        return 1
    return 0


def _run_analyze(args: argparse.Namespace) -> int:
    now = _parse_now(args.now)
    if args.config is not None:
        config = load_config(args.config)
    else:
        config = Config()

    results = _parse_inputs(args.inputs, args.input_type, config)

    # Fatal parse errors short-circuit before analysis (exit 2).
    if any(err.fatal for r in results for err in r.errors):
        for r in results:
            for err in r.errors:
                if err.fatal:
                    print(
                        f"fatal: {r.source_file}:{err.line_no}: {err.reason}",
                        file=sys.stderr,
                    )
        return 2

    events, _errors = build_stream(results)
    ctx = AnalysisContext(
        config=config,
        baseline_events=(),
        geo_resolver=NullResolver(),
        now=now,
        tz=ZoneInfo(config.ingest.log_timezone),
    )
    detectors = build_detectors(config)
    alerts = run_detectors(events, ctx, detectors)

    if args.format == "json":
        print(render_json(results, events, alerts, now))
    else:
        print(render_text(results, events, alerts, now, timeline=args.timeline), end="")

    return _exit_code(alerts, results, config)


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns a process exit code (0/1/2)."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command != "analyze":
        parser.print_help()
        return 0
    try:
        return _run_analyze(args)
    except UsageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (ValueError, OSError) as exc:
        # Bad config (ValueError from load_config) or I/O error -> usage exit 2.
        print(f"error: {exc}", file=sys.stderr)
        return 2

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
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from . import __version__, ids
from .config import Config, Geo, load_config, validate_config
from .detectors.newsourceip import compute_known_sets
from .engine import (
    build_detectors,
    build_stream,
    derive_baseline,
    run_detectors,
)
from .geo import (
    CachingResolver,
    MaxMindResolver,
    NullResolver,
    StaticResolver,
)
from .models import Alert, AuthMethod, LoginEvent, Outcome, Severity
from .parsers import AuthLogParser, CsvParser
from .parsers.base import ParseResult
from .protocols import AnalysisContext, GeoResolver
from .report import render_json, render_text
from .state import load_state, save_state

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
    analyze.add_argument(
        "--geo-db", type=str, default=None,
        help="Local GeoLite2 .mmdb path; overrides config and implies maxmind.",
    )
    analyze.add_argument(
        "--baseline", nargs="+", default=None,
        help="Baseline file(s) for R5; overrides config baseline_source.",
    )
    analyze.add_argument(
        "--output", type=str, default=None,
        help="Write the report to this file instead of stdout.",
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


def _build_resolver(geo: Geo) -> GeoResolver:
    """Build a cache-wrapped resolver from the (validated) geo config."""
    inner: GeoResolver
    if geo.resolver == "static":
        assert geo.static_path is not None  # ensured by validation
        inner = StaticResolver(geo.static_path)
    elif geo.resolver == "maxmind":
        assert geo.mmdb_path is not None  # ensured by validation
        inner = MaxMindResolver(geo.mmdb_path)
    else:
        inner = NullResolver()
    return CachingResolver(inner)


def _apply_geo_override(config: Config, geo_db: str | None) -> Config:
    """Apply a ``--geo-db`` override: force maxmind with the given mmdb path."""
    if geo_db is None:
        return config
    new_geo = replace(config.geo, resolver="maxmind", mmdb_path=geo_db)
    new_config = replace(config, geo=new_geo)
    validate_config(new_config)
    return new_config


def _build_baseline(
    args: argparse.Namespace,
    config: Config,
    events: tuple[LoginEvent, ...],
) -> tuple[LoginEvent, ...]:
    """Resolve R5 baseline events from ``--baseline`` or config baseline_source.

    ``--baseline`` (file mode) takes precedence. Otherwise a config
    ``baseline_source`` of ``cutoff_ts:``/``first_n_percent:`` is derived from
    the analyzed stream; a bare existing path is parsed as a file. Unset -> ().
    """
    if args.baseline:
        results = _parse_inputs(args.baseline, "auto", config)
        base_events, _errors = build_stream(results)
        return base_events
    source = config.r5.baseline_source
    if source and not source.startswith(("cutoff_ts:", "first_n_percent:")):
        # Bare path baseline -> parse the file(s).
        if Path(source).is_file():
            results = _parse_inputs([source], "auto", config)
            base_events, _errors = build_stream(results)
            return base_events
    return derive_baseline(events, source)


def _state_events(
    state: dict[str, set[str]], now: datetime
) -> tuple[LoginEvent, ...]:
    """Synthesize baseline-seed events from persisted R5 known-IP state.

    These carry the per-user known IPs as already-seen successes so the detector
    treats them as known (and the user as non-empty-baseline). Built in sorted
    order for determinism; ``raw`` marks them as synthetic state seeds.
    """
    events: list[LoginEvent] = []
    line_no = 0
    for user in sorted(state):
        for ip in sorted(state[user]):
            line_no += 1
            raw = f"r5-state-seed {user} {ip}"
            events.append(
                LoginEvent(
                    event_id=ids.event_id("<r5-state>", line_no, raw),
                    timestamp=now,
                    username=user,
                    source_ip=ip,
                    source_port=None,
                    outcome=Outcome.SUCCESS,
                    auth_method=AuthMethod.UNKNOWN,
                    hostname=None,
                    raw=raw,
                    source_file="<r5-state>",
                    line_no=line_no,
                )
            )
    return tuple(events)


def _run_analyze(args: argparse.Namespace) -> int:
    now = _parse_now(args.now)
    if args.config is not None:
        config = load_config(args.config)
    else:
        config = Config()
    config = _apply_geo_override(config, args.geo_db)

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
    baseline_events = _build_baseline(args, config, events)
    # Opt-in R5 persistence: merge prior known-IP state into the baseline seed.
    if config.r5.persist and config.r5.state_path is not None:
        prior = load_state(config.r5.state_path)
        baseline_events = _state_events(prior, now) + baseline_events
    ctx = AnalysisContext(
        config=config,
        baseline_events=baseline_events,
        geo_resolver=_build_resolver(config.geo),
        now=now,
        tz=ZoneInfo(config.ingest.log_timezone),
    )
    detectors = build_detectors(config)
    alerts = run_detectors(events, ctx, detectors)

    # Write the updated R5 known-sets back (atomic, deterministic).
    if config.r5.persist and config.r5.state_path is not None:
        updated = compute_known_sets(baseline_events, events, config.r5.only_success)
        save_state(config.r5.state_path, updated)

    if args.format == "json":
        # Trailing newline mirrors the historical stdout (print) behavior.
        report = render_json(results, events, alerts, now) + "\n"
    else:
        report = render_text(results, events, alerts, now, timeline=args.timeline)

    if args.output is not None:
        Path(args.output).write_text(report, encoding="utf-8")
    else:
        sys.stdout.write(report)

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

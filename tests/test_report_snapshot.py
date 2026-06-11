"""Byte-equal golden JSON snapshot test with an injected clock."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from logsentry.config import load_config
from logsentry.engine import build_detectors, build_stream, run_detectors
from logsentry.geo import NullResolver
from logsentry.parsers import AuthLogParser
from logsentry.protocols import AnalysisContext
from logsentry.report import render_json

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
GOLDEN = FIXTURES / "golden_report.json"

_NOW = datetime(2026, 1, 10, 20, 0, 0, tzinfo=UTC)


def test_json_byte_equal_to_golden() -> None:
    cfg = load_config(FIXTURES / "analyze.toml")
    # Use the same relative path string the golden was generated with, so
    # event_ids (which hash source_file) match byte-for-byte.
    result = AuthLogParser(cfg).parse(Path("tests/fixtures/burst.log"))
    events, _errors = build_stream([result])
    ctx = AnalysisContext(
        config=cfg,
        baseline_events=(),
        geo_resolver=NullResolver(),
        now=_NOW,
        tz=ZoneInfo(cfg.ingest.log_timezone),
    )
    alerts = run_detectors(events, ctx, build_detectors(cfg))
    rendered = render_json([result], events, alerts, _NOW)
    expected = GOLDEN.read_text(encoding="utf-8")
    # Golden file is the CLI's stdout (print adds one trailing newline).
    assert rendered + "\n" == expected


def test_json_deterministic_across_runs() -> None:
    cfg = load_config(FIXTURES / "analyze.toml")
    result = AuthLogParser(cfg).parse(FIXTURES / "burst.log")
    events, _ = build_stream([result])
    ctx = AnalysisContext(
        config=cfg, baseline_events=(), geo_resolver=NullResolver(),
        now=_NOW, tz=ZoneInfo(cfg.ingest.log_timezone),
    )
    alerts = run_detectors(events, ctx, build_detectors(cfg))
    a = render_json([result], events, alerts, _NOW)
    b = render_json([result], events, alerts, _NOW)
    assert a == b

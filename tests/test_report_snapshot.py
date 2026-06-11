"""Byte-equal golden JSON snapshot test with an injected clock."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from logsentry.config import load_config
from logsentry.engine import build_detectors, build_stream, run_detectors
from logsentry.geo import CachingResolver, NullResolver, StaticResolver
from logsentry.parsers import AuthLogParser
from logsentry.protocols import AnalysisContext
from logsentry.report import render_json

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
GOLDEN = FIXTURES / "golden_report.json"
GOLDEN_TRAVEL = FIXTURES / "golden_travel.json"
GOLDEN_CORRELATED = FIXTURES / "golden_correlated.json"

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


def test_phase2_golden_unchanged_with_r3_registered() -> None:
    # Explicit guard: the R1/R2 golden must remain byte-identical now that R3
    # is registered. burst.log resolves no geo, so R3 adds nothing.
    cfg = load_config(FIXTURES / "analyze.toml")
    result = AuthLogParser(cfg).parse(Path("tests/fixtures/burst.log"))
    events, _ = build_stream([result])
    ctx = AnalysisContext(
        config=cfg, baseline_events=(), geo_resolver=NullResolver(),
        now=_NOW, tz=ZoneInfo(cfg.ingest.log_timezone),
    )
    alerts = run_detectors(events, ctx, build_detectors(cfg))
    rendered = render_json([result], events, alerts, _NOW)
    assert rendered + "\n" == GOLDEN.read_text(encoding="utf-8")
    # No alert carries a details key (R1/R2 only).
    assert '"details"' not in rendered


def test_golden_travel_byte_equal() -> None:
    cfg = load_config(FIXTURES / "travel.toml")
    result = AuthLogParser(cfg).parse(Path("tests/fixtures/travel.log"))
    events, _ = build_stream([result])
    resolver = CachingResolver(StaticResolver(FIXTURES / "geo_static.csv"))
    ctx = AnalysisContext(
        config=cfg, baseline_events=(), geo_resolver=resolver,
        now=_NOW, tz=ZoneInfo(cfg.ingest.log_timezone),
    )
    alerts = run_detectors(events, ctx, build_detectors(cfg))
    rendered = render_json([result], events, alerts, _NOW)
    assert rendered + "\n" == GOLDEN_TRAVEL.read_text(encoding="utf-8")


def test_golden_correlated_byte_equal() -> None:
    cfg = load_config(FIXTURES / "correlated.toml")
    result = AuthLogParser(cfg).parse(Path("tests/fixtures/correlated.log"))
    events, _ = build_stream([result])
    ctx = AnalysisContext(
        config=cfg, baseline_events=(), geo_resolver=NullResolver(),
        now=_NOW, tz=ZoneInfo(cfg.ingest.log_timezone),
    )
    alerts = run_detectors(events, ctx, build_detectors(cfg))
    rendered = render_json([result], events, alerts, _NOW)
    assert rendered + "\n" == GOLDEN_CORRELATED.read_text(encoding="utf-8")

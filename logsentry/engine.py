"""Analysis engine: merge events, run detectors, rank alerts.

Pure orchestration — no I/O, no wall-clock. All ordering is via explicit,
stable sort keys so output is fully deterministic.
"""

from __future__ import annotations

from collections.abc import Sequence

from .config import Config
from .detectors import BruteForceDetector, FailedThenSuccessDetector
from .models import Alert, LoginEvent
from .parsers.base import ParseError, ParseResult
from .protocols import AnalysisContext, Detector
from .scoring import rank_alerts


def build_stream(
    results: Sequence[ParseResult],
) -> tuple[tuple[LoginEvent, ...], tuple[ParseError, ...]]:
    """Merge parse results into one ordered event stream plus all errors.

    Events are stable-sorted by ``(timestamp, source_file, line_no, event_id)``;
    errors are ordered by ``(source_file, line_no)``.
    """
    events: list[LoginEvent] = []
    # ParseError carries no source_file; pair each with its result's file so
    # aggregation order is deterministic.
    indexed_errors: list[tuple[str, int, ParseError]] = []
    for result in results:
        events.extend(result.events)
        for err in result.errors:
            indexed_errors.append((result.source_file, err.line_no, err))

    events.sort(
        key=lambda e: (e.timestamp, e.source_file, e.line_no, e.event_id)
    )
    indexed_errors.sort(key=lambda t: (t[0], t[1]))
    ordered_errors = tuple(err for _, _, err in indexed_errors)
    return tuple(events), ordered_errors


def build_detectors(config: Config) -> tuple[Detector, ...]:
    """Build the ordered detector registry from config (R1, R2 for now)."""
    return (BruteForceDetector(), FailedThenSuccessDetector())


def run_detectors(
    events: tuple[LoginEvent, ...],
    ctx: AnalysisContext,
    detectors: Sequence[Detector],
) -> tuple[Alert, ...]:
    """Run each detector, concatenate alerts, then rank them deterministically."""
    collected: list[Alert] = []
    for detector in detectors:
        collected.extend(detector.analyze(list(events), ctx))
    return rank_alerts(tuple(collected))

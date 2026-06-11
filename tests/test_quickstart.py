"""Quickstart: run the bundled sample and assert the rule set + count.

Stable assertions (rule_ids present + total count), not a byte-golden, so the
sample stays robust to cosmetic description changes.
"""

from __future__ import annotations

import json
from pathlib import Path

from logsentry.cli import main

ROOT = Path(__file__).resolve().parents[1]
NOW = "2026-01-10T20:00:00+00:00"


def test_sample_emits_all_five_rules(capsys, tmp_path) -> None:  # type: ignore[no-untyped-def]
    out_file = tmp_path / "report.json"
    code = main([
        "analyze", "examples/sample_auth.log",
        "--baseline", "examples/sample_baseline.log",
        "--config", "examples/sample.toml",
        "--now", NOW,
        "--format", "json",
        "--output", str(out_file),
    ])
    # Exit 1: at least one HIGH alert (fail_severity = HIGH).
    assert code == 1
    report = json.loads(out_file.read_text(encoding="utf-8"))
    assert report["summary"]["total_alerts"] == 5
    rule_ids = sorted(a["rule_id"] for a in report["alerts"])
    assert rule_ids == ["R1", "R2", "R3", "R4", "R5"]
    # generated_at honors the injected clock (determinism).
    assert report["generated_at"] == "2026-01-10T20:00:00+00:00"
    assert report["tool_version"] == "0.1.0"

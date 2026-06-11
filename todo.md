# Phase 2 — Engine + R1 + R2 (todo)

- [x] Task 1 — engine.py: build_stream (stable sort), run_detectors, registry
- [x] Task 2 — detectors/bruteforce.py (R1), detectors/failsucc.py (R2)
- [x] Task 3 — scoring.py: severity bases, R1/R2 formulas, rank key
- [x] Task 4 — report/json_report.py, report/text_report.py
- [x] Task 5 — cli.py + thin __main__.py; [output].fail_severity
- [x] Task 6 — fixtures + tests (engine, scoring, R1, R2, snapshot, exit codes)

## Verification

- [x] ruff / mypy --strict / pytest green (59 tests)
- [x] both CLI runs (json exit=1 / text exit=1) as expected

## Out of scope (Phase 2)

- No R3/geo, no R4, no baseline wiring, no correlation. No network.
- No new runtime deps. No Phase 0/1 public signature changes — extend only.

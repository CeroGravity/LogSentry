# Phase 5 — Polish, Docs, Optional Correlation, Hardening (todo)

- [x] Task 1 — version 0.1.0 single-source; regenerate goldens; guarded diff (only tool_version)
- [x] Task 2 — README.md (scope, install, quickstart, 5-rule table, config+CLI ref, exit codes, determinism)
- [x] Task 3 — THREAT_MODEL.md (per-rule FP/FN, sandwich gap, path-sensitivity, per-run baseline, determinism, local-only)
- [x] Task 4 — CHANGELOG.md [0.1.0] covering Phases 0–5 + FP-1.1
- [x] Task 5 — examples/ sample + quickstart + test_quickstart.py
- [x] Task 6 — timeline polish (evidence markers) + --output PATH; default unchanged
- [x] Task 7 — optional correlation R0 (off by default) + golden_correlated.json
- [x] Task 8 — hardening: no stray stubs; --help capture; ruff/mypy/pytest green

## Verification

- [x] ruff / mypy --strict / pytest green (104 tests)
- [x] guarded golden diff: only tool_version line changed
- [x] correlation off → existing goldens byte-equal
- [x] grep TODO/NotImplementedError clean

## Done — v0.1.0

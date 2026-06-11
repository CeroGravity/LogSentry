# Phase 4 — R4 Off-Hours + R5 New-Source-IP (todo)

- [x] Task 1 — models: OffHoursDetail, NewSourceIPDetail, AlertDetail union, Alert.details widened
- [x] Task 2 — detectors/offhours.py (R4, MEDIUM)
- [x] Task 3 — detectors/newsourceip.py (R5, LOW) + empty-baseline silence
- [x] Task 4 — engine.derive_baseline (cutoff/percent) + CLI --baseline + file mode
- [x] Task 5 — uniform allowlists (shared _common.is_allowlisted) across R1–R5
- [x] Task 6 — scoring.score_r4 / score_r5
- [x] Task 7 — json/text serialization; config baseline_source validation; example toml
- [x] Task 8 — fixtures + tests (offhours, newsourceip, baseline, allowlist, snapshot)

## Verification

- [x] ruff / mypy --strict / pytest green (98 tests)
- [x] import scan: geoip2/maxminddb only in geo.py; no network imports
- [x] Phase 2 AND Phase 3 goldens byte-identical

## Out of scope (Phase 4)

- No correlation. No schema bump (additive only). No network. No new deps.

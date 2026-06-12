# Phase 6 — Enhancements v0.2.0 (todo)

- [x] Task A — severity-primary rank_key + cross-severity test
- [x] Task B — R3 sandwich-gap fix (filter-to-resolved then pair); travel_sandwich fixture; travel.log = TERMINAL case (no golden change)
- [x] Task C — R5 persistent baseline (opt-in, default OFF): persist/state_path; atomic sorted JSON; load+merge+writeback
- [x] Task D — R4 per-(user,local_date) collapsing; OffHoursDetail += event_count,last_local_time
- [x] Task E — version 0.2.0; 3 goldens regenerated; every diff explained; CHANGELOG + README + THREAT_MODEL

## Verification

- [x] ruff / mypy --strict / pytest green (112 tests)
- [x] every golden diff explained (report/travel: version-only; correlated: version + R4-collapse)
- [x] persist OFF → prior behavior byte-identical (goldens hold)
- [x] grep TODO/NotImplementedError clean

## Done — v0.2.0

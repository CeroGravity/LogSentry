# LogSentry sample

A self-contained scenario that triggers all five detection rules.

## Run

```sh
python -m logsentry analyze examples/sample_auth.log \
  --baseline examples/sample_baseline.log \
  --config examples/sample.toml \
  --now 2026-01-10T20:00:00+00:00 \
  --format text
```

`--now` is fixed so the output (`generated_at`) is reproducible. Exit code is
`1` because at least one alert is `>= HIGH` (the configured `fail_severity`).

## Expected alerts (5 total)

| rule | severity | who | why |
|------|----------|-----|-----|
| R1 brute_force_burst | HIGH | `89.40.10.10` | 5 failed logins in ~32s targeting `root`/`oracle` |
| R2 failed_then_success | CRITICAL | `eve` | 3 failures then a success from `89.40.10.20` |
| R3 impossible_travel | HIGH | `bob` | New York → London in 30 min (~11140 km/h) |
| R4 off_hours_access | MEDIUM | `carol` | Saturday login (non-business day, America/New_York) |
| R5 new_source_ip_per_user | LOW | `dave` | Logs in from `89.40.10.30`, unseen vs the baseline |

`dave`'s known IPs are seeded from `sample_baseline.log` (`45.32.10.5`,
`45.32.10.6`); the new IP raises R5. Geo for R3 comes from `sample_geo.csv`
(offline, no network).

## Files

- `sample_auth.log` — the analyzed input (sshd auth lines).
- `sample_baseline.log` — prior known-good logins seeding R5 known-sets.
- `sample_geo.csv` — static IP → location map for R3.
- `sample.toml` — config wiring static geo + R1–R5 thresholds.

## Try the timeline and correlation

```sh
# Annotated chronological event list (evidence markers like *R1, *R3):
python -m logsentry analyze examples/sample_auth.log \
  --baseline examples/sample_baseline.log --config examples/sample.toml \
  --now 2026-01-10T20:00:00+00:00 --format text --timeline
```

Cross-rule correlation is off by default; enable it with `[correlation]
enabled = true` in a config to get synthetic `R0` "Correlated activity" alerts
for entities implicated across multiple rules.

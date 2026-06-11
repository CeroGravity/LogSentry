# LogSentry

Defensive auth-log anomaly detector. **Blue-team only — analysis only, no
offensive capability.** It ingests Linux `auth.log` / sshd lines or a CSV of
login events and emits a deterministic, ranked set of alerts.

## Scope

- Defensive analysis only. No exploitation, credential attacks, or log
  tampering — by design, and refused as a feature.
- **No network.** Only local file reads + report output. Optional GeoIP reads a
  **local** `.mmdb`; it never downloads or queries online.
- Deterministic by construction: an injected clock is the only wall-clock;
  explicit timezones; stable sorts; integer scoring; fixed hashing for IDs.

## Install

Requires **Python 3.11+** (stdlib only for the core).

```sh
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"          # ruff, mypy, pytest for development
# Optional, only for the MaxMind geo backend:
pip install geoip2
```

Run as a module: `python -m logsentry ...`.

## Quickstart

```sh
python -m logsentry analyze examples/sample_auth.log \
  --baseline examples/sample_baseline.log \
  --config examples/sample.toml \
  --now 2026-01-10T20:00:00+00:00 \
  --format text
```

This sample triggers all five rules. See [examples/README.md](examples/README.md)
for the expected alert set.

## Detection rules

| ID | What it flags | Key params | Severity |
|----|---------------|-----------|----------|
| R1 brute_force_burst | Rapid repeated failed auths from a source | `window_seconds`, `min_failures`, `per_user` | HIGH |
| R2 failed_then_success | Failures then a success for the same entity in a window | `window_seconds`, `min_preceding_failures`, `require_same_source_ip` | CRITICAL |
| R3 impossible_travel | Same user in two locations too far apart too fast | `max_kmh`, `min_distance_km`, `consider_failures` | HIGH |
| R4 off_hours_access | Successful login outside business hours | `timezone`, `business_days`, `business_start`, `business_end`, `only_success` | MEDIUM |
| R5 new_source_ip_per_user | First auth from an unseen IP per user vs baseline | `baseline_source`, `only_success` | LOW |

Optional `R0 Correlated activity` (off by default) groups an entity implicated
across multiple rules into one synthetic alert.

## Input formats

- **auth.log / sshd**: traditional syslog (`MMM DD HH:MM:SS`, needs
  `ingest.log_year`) or ISO8601 with offset. Only `Accepted` / `Failed` /
  `Failed ... invalid user` lines emit events; `pam_unix` and standalone
  `Invalid user` lines are ignored to avoid double-counting.
- **CSV**: header-based; map your columns in `[ingest.csv]`. Required logical
  fields: `timestamp, username, source_ip, outcome`.

## Configuration reference

All sections are optional and fall back to defaults unless noted. See
[`logsentry.example.toml`](logsentry.example.toml) for the fully documented file.

| Section / key | Default | Meaning |
|---------------|---------|---------|
| `[r1] window_seconds` | `60` | Brute-force sliding window (s) |
| `[r1] min_failures` | `10` | Failures in window to trigger |
| `[r1] per_user` | `false` | Key by `(ip, user)` instead of `ip` |
| `[r2] window_seconds` | `300` | Window for the following success |
| `[r2] min_preceding_failures` | `5` | Failures required before success (≥1) |
| `[r2] require_same_source_ip` | `true` | Success must share the failures' IP |
| `[r3] max_kmh` | `900` | Speed above which travel is impossible (>0) |
| `[r3] min_distance_km` | `500` | Ignore hops shorter than this |
| `[r3] consider_failures` | `false` | Also weigh failed auths |
| `[r4] timezone` | `"UTC"` | IANA tz (**required** in practice for R4) |
| `[r4] business_days` | `[0..4]` | 0=Mon..6=Sun |
| `[r4] business_start` / `business_end` | `08:00` / `18:00` | Inclusive start, exclusive end |
| `[r4] only_success` | `true` | Only alert on successful logins |
| `[r5] baseline_source` | unset | Path \| `cutoff_ts:<ISO>` \| `first_n_percent:<1..100>` |
| `[r5] only_success` | `true` | Only consider successful logins |
| `[allowlists] ips` / `users` | `[]` | Entities suppressed across all rules |
| `[output] fail_severity` | `"HIGH"` | Exit 1 if any alert ≥ this severity |
| `[geo] resolver` | `"null"` | `null` \| `static` \| `maxmind` |
| `[geo] static_path` / `mmdb_path` | unset | Local CSV / local `.mmdb` |
| `[correlation] enabled` | `false` | Emit synthetic `R0` alerts |
| `[correlation] min_rules` | `2` | Distinct rules to correlate (≥2) |
| `[ingest] log_timezone` | `"UTC"` | **Required** IANA tz for year-less/naive ts |
| `[ingest] log_year` | unset | **Required** for year-less syslog timestamps |
| `[ingest.csv] ...` | — | Column map, `outcome_map`, `auth_method_map`, `timestamp_format` |

## CLI reference

```
python -m logsentry analyze INPUT [INPUT ...] [options]
```

| Flag | Description |
|------|-------------|
| `--config PATH` | Config TOML (defaults applied if omitted) |
| `--format json\|text` | Output format (default `text`) |
| `--input-type auto\|auth\|csv` | Input type; `auto` detects by extension |
| `--timeline` | Append a chronological event list (text); cited events marked `*<rule_id>` |
| `--now ISO8601` | Inject the clock for `generated_at` (default: real UTC now) |
| `--geo-db PATH` | Local `.mmdb`; overrides config, implies `maxmind` |
| `--baseline PATH [PATH ...]` | Baseline file(s) for R5; overrides config |
| `--output PATH` | Write the report to a file instead of stdout |

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success; no alert reached `fail_severity` |
| `1` | At least one alert ≥ `fail_severity` (default HIGH) |
| `2` | Usage error, fatal parse error (e.g. missing required CSV column), or bad config |

## Determinism

Output is reproducible: the only wall-clock is the injected `--now`
(`generated_at`). Timestamps convert via explicit configured timezone/year,
never the implicit system tz. All ordering uses stable sorts with explicit
tiebreakers; scoring is integer math; alert/event IDs use a fixed hash. JSON is
emitted with `sort_keys=True`, so identical inputs produce byte-identical
reports.

## Limitations

See [THREAT_MODEL.md](THREAT_MODEL.md) for per-rule false-positive and
false-negative / evasion notes (including the R3 consecutive-pair "sandwich
gap", `event_id` path-sensitivity, and the per-run R5 baseline) plus the
determinism and data-handling guarantees.

## Development

```sh
ruff check .
mypy --strict logsentry
pytest -q
```

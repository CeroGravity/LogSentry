# LogSentry — Threat Model & Limitations

LogSentry is a **defensive, blue-team-only** auth-log anomaly detector. It is
analysis software: it reads logs and emits ranked alerts. It performs no
authentication, no active probing, and has no offensive capability.

## What it does

- Parses Linux `auth.log` / sshd lines and CSV login exports into a normalized,
  UTC, ordered event stream.
- Runs five detection rules (R1–R5) plus an optional cross-rule correlation
  pass (R0, off by default).
- Produces a deterministic JSON or text report with ranked alerts and evidence.

## What it does NOT do

- It does not block, throttle, or respond to activity — detection only.
- It does not make network calls. The optional MaxMind backend reads a **local**
  `.mmdb` file; it never downloads databases or performs online lookups.
- It does not authenticate, escalate, tamper with logs, or generate traffic.
- It does not persist state between runs (no learned database).

## Per-rule detection logic, FP and FN/evasion notes

### R1 brute_force_burst (HIGH)
- **Logic:** failures grouped per source IP (or `(ip, user)`); failures inside a
  dense `window_seconds` span of `≥ min_failures` are coalesced into bursts; one
  alert per burst.
- **FP risk:** misconfigured clients, expired credentials, or monitoring probes
  can produce benign failure bursts. Suppress with `[allowlists].ips`.
- **FN / evasion:** an attacker pacing attempts below `min_failures` per
  `window_seconds` (low-and-slow) evades the burst test. Bursts split only when
  the gap **exceeds** the window.

### R2 failed_then_success (CRITICAL)
- **Logic:** for each success, count preceding in-window failures for the same
  `username` (and IP if `require_same_source_ip`); alert at `≥
  min_preceding_failures`.
- **FP risk:** a user fat-fingering a password several times then succeeding is
  benign-but-flagged. Tune thresholds or allowlist service accounts.
- **FN / evasion:** failures spread beyond `window_seconds`, or a success from a
  different IP when `require_same_source_ip=true`, are not correlated.

### R3 impossible_travel (HIGH)
- **Logic:** per user, events are **first filtered to those with a real resolved
  location** (public, coordinates returned); consecutive *resolved* events are
  then compared; if implied speed `> max_kmh` and distance `≥ min_distance_km`,
  alert.
- **FP risk:** VPNs, corporate proxies, NAT/CGNAT, and mobile carrier egress can
  place a user in a far-off city, producing impossible-travel false positives.
- **Sandwich gap — CLOSED (v0.2.0):** the prior consecutive-pair logic could be
  evaded by inserting an unresolved/private login between two resolved ones,
  which split the pair and hid the hop. R3 now drops unresolved/private events
  from the sequence and pairs the surviving resolved events, so an interior
  unresolved event no longer breaks the comparison.
- **Residual tradeoff:** filtering to resolved endpoints means a genuinely
  *intermediate* real location (a legitimate stop whose IP happens to resolve to
  a third city) is also skipped over — comparing the outer two resolved
  endpoints can now produce a false positive where the true path was feasible
  via the unshown intermediate hop.
- **FN / evasion:** low-and-slow movement under `max_kmh`, or activity from only
  unresolved IPs, still evades R3.

### R4 off_hours_access (MEDIUM)
- **Logic:** successful logins converted to `r4.timezone`; alert if on a
  non-business day or outside `[business_start, business_end)`.
- **FP risk:** legitimate shift work, on-call, or global teams routinely log in
  off-hours. Scope the business window/days per environment; allowlist as needed.
- **FN / evasion:** activity inside the configured window is never flagged; an
  attacker active during business hours evades R4.

### R5 new_source_ip_per_user (LOW)
- **Logic:** per-user known-IP set seeded from the baseline; the first analyzed
  login from an unseen IP raises one alert, then that IP becomes known.
- **FP risk:** roaming users, new devices, and dynamic IPs trip R5. It is LOW
  severity for this reason.
- **FN / evasion — baseline scope (required note):** by default the known-set is
  built **only** from `baseline_events` at the start of each run, with **no
  persistent state across runs**. A user with an **empty** baseline is learned
  silently and never alerts (first-run flooding guard), so genuinely new
  infrastructure for such a user is not flagged until a baseline exists.
- **Opt-in persistence (v0.2.0, default OFF):** with `r5.persist=true` and
  `r5.state_path`, per-user known-IP sets are loaded/merged before analysis and
  written back afterwards, so learned IPs carry across runs. The **state file
  holds usernames and IP addresses** (no secrets) — protect it like the logs it
  derives from. It is read/written locally only; no network. Off by default →
  no read, no write.

### R0 Correlated activity (optional, off by default)
- **Logic:** when enabled, an entity (username, else source IP) implicated
  across `≥ min_rules` distinct rules yields one synthetic alert.
- **FP/FN:** inherits the constituents'; correlation neither adds nor removes
  base detections, it only summarizes them.

## Cross-cutting: `event_id` path-sensitivity (required note)

`event_id` is a fixed hash of `(source_file, line_no, raw)`, where
`source_file` is **the input path string as passed**. The same log analyzed via
a different path (relative vs absolute, or a different filename) yields
different `event_id`s — and therefore different `alert_id`s and evidence hashes.
**Reproducibility is per-path**: byte-identical output requires the same input
path string (this is why the golden fixtures are generated and tested with a
fixed relative path).

## Determinism guarantees

- The only wall-clock is the injected `now` (`--now` / `AnalysisContext.now`),
  surfaced solely as `generated_at`. No library code calls `datetime.now()`.
- Timestamps convert via explicit configured timezone and year; never the
  implicit system timezone. Year-less syslog requires `ingest.log_year`.
- All ordering uses stable sorts with explicit tiebreakers; no set iteration
  reaches output. Scoring is integer math. IDs use a fixed SHA-1 truncation.
- Alerts rank by **severity first** (a CRITICAL never below a HIGH); **score
  breaks ties within a severity**, then start time, `rule_id`, `dedup_key`.
- JSON uses `sort_keys=True` → byte-identical reports for identical inputs.

## Data handling

- All input is read from local files; all output goes to stdout or a local file
  (`--output`).
- No network egress of any kind.
- No secrets are required or logged; raw log lines are preserved as evidence
  only within the report the operator already controls.
- The optional R5 state file (`r5.state_path`) holds usernames + known IPs and
  is read/written atomically on the local filesystem only; protect it like the
  logs. It is absent unless `r5.persist` is enabled.

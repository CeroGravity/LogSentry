# CLAUDE.md — LogSentry

> Project rules. On any conflict with generic/global rules, **project rules win.**

## Project

- **LogSentry** — defensive auth-log anomaly detector. **Blue-team only.**
- Ingest Linux `auth.log`/SSH logs or CSV of login events.
- Flag: brute-force bursts, impossible-travel, off-hours access,
  new-source-IP-per-user, failed→success patterns.
- Output: deterministic timeline + ranked alerts. Analysis only.

## Hard scope rule (non-negotiable)

- Defensive analysis only.
- **Refuse any offensive capability, exploitation, credential attacks,
  or log-tampering extension — now and in every future phase.**
- No network calls except optional, explicit GeoIP lookups (Phase 3+).

## Determinism mandate (cross-cutting, all phases)

- No wall-clock in output except an injected `now`. No bare
  `datetime.now()` in library code.
- Stable sorts with explicit tiebreakers everywhere. No raw set
  iteration into output.
- Fixed hash algorithm for IDs. Timezone always explicit; never implicit
  system tz.

## Stack constraints (locked)

- Python 3.11+ (`tomllib`, `zoneinfo` stdlib). Sync, dataclasses, argparse.
- Core stdlib-only. Optional deps `geoip2`/`maxminddb` — deferred to
  Phase 3, NOT before.
- Dev tooling: `ruff`, `mypy --strict`, `pytest`.
- **No async. No Docker. No PyPI publish.**
- Package `logsentry/` + `python -m logsentry`.

## Geo decision (locked)

- Pluggable `GeoResolver`: `StaticResolver` (CSV map, offline,
  deterministic) + `MaxMindResolver` (GeoLite2 `.mmdb`) + `NullResolver`.
- Light, free, optional deps only. Phase 0: protocol stub only — no geo
  logic, no deps.

## Detection rule registry (logic in later phases)

- **R1 brute_force_burst** — rapid repeated failed auths from a source.
- **R2 failed_then_success** — failures then a success for same entity in window.
- **R3 impossible_travel** — same user, two locations too far apart too fast.
- **R4 off_hours_access** — successful login outside configured business hours.
- **R5 new_source_ip_per_user** — first auth from an unseen IP per user vs baseline.

## Report protocol

- Every phase handoff uses the **12-section report format** defined in the
  Execution Pack.
- **§8 Verification Output must be VERBATIM** (full `ruff` / `mypy` /
  `pytest` output, unsummarized). Compression = auto-fail.

## Phase discipline

- One phase per session. No scope creep.
- Maintain a `todo.md` per session.
- Do not add detector/parser/geo/IO logic outside the phase that owns it.

---

## Generic engineering rules (preserved; project rules override on conflict)

- Be concise and direct. Show commands before explanations.
- Read existing code before changing architecture. Prefer minimal diffs.
- Prefer simple solutions; avoid unnecessary dependencies.
- Prefer explicit code over abstractions. Optimize for maintainability.
- Clear naming. Avoid duplicated logic. Handle edge cases explicitly.
- Fail loudly on invalid state. Comments only when necessary.
- Never hardcode secrets. Never expose credentials in logs. Env vars for config.
- Run relevant tests after changes. Include verification steps.
- Git: never force-push, delete branches, or run destructive commands
  without asking.

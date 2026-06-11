# LogSentry

Defensive auth-log anomaly detector. **Blue-team only — analysis only, no
offensive capability.**

## Purpose

Ingest Linux `auth.log` / SSH logs or a CSV of login events and flag
suspicious authentication patterns as a deterministic timeline plus ranked
alerts.

## Scope

- Defensive analysis only. No exploitation, credential attacks, or log
  tampering — by design and refused as a feature in every phase.
- Core is Python stdlib-only. No async, no Docker, no PyPI publish.
- Deterministic by construction: injected clock, explicit timezones, stable
  sorts, fixed hashing for IDs.

## Detection rules

| ID | Name | Intent |
|----|------|--------|
| R1 | brute_force_burst | Rapid repeated failed auths from a source. |
| R2 | failed_then_success | Failures then a success for the same entity in a window. |
| R3 | impossible_travel | Same user in two locations too far apart too fast. |
| R4 | off_hours_access | Successful login outside configured business hours. |
| R5 | new_source_ip_per_user | First auth from an unseen IP per user vs baseline. |

> Phase 0 ships contracts and tooling only. Detector logic lands in later
> phases.

## Usage (skeleton)

```sh
python -m logsentry --help
```

Configuration is TOML; see [`logsentry.example.toml`](logsentry.example.toml)
for every key and its default.

## Development

```sh
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
ruff check .
mypy --strict logsentry
pytest -q
```

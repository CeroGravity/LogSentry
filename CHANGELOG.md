# Changelog

All notable changes to LogSentry are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-06-11

First release: a complete, documented, deterministic blue-team auth-log
anomaly detector built across six phases.

### Added

- **Foundations (Phase 0):** package skeleton, frozen-dataclass model
  (`LoginEvent`, `GeoLocation`, `Alert`), `Detector`/`GeoResolver` protocols,
  `AnalysisContext` with an injected clock, deterministic ID helpers, and the
  `tomllib`-based `Config` loader. Tooling: `ruff`, `mypy --strict`, `pytest`.
- **Ingestion (Phase 1):** `AuthLogParser` (syslog + ISO8601 sshd lines) and
  `CsvParser`, both producing normalized UTC events; malformed input is
  collected as non-fatal `ParseError`s rather than crashing. Config value-range
  and IANA-timezone validation.
- **Engine + R1/R2 (Phase 2):** `build_stream` (stable-sorted merge),
  `run_detectors`, integer scoring + ranking, deterministic JSON/text reports,
  and the `analyze` CLI with exit codes 0/1/2. Rules **R1 brute_force_burst**
  and **R2 failed_then_success**.
- **Geo + R3 (Phase 3):** pluggable resolvers — `NullResolver`,
  `StaticResolver` (offline CSV), `MaxMindResolver` (local `.mmdb`, lazy
  optional `geoip2` import) and a `CachingResolver`; `haversine` distance; rule
  **R3 impossible_travel** with structured `details`.
- **R4/R5 + baseline (Phase 4):** **R4 off_hours_access** and **R5
  new_source_ip_per_user**; baseline ingestion via file path, `cutoff_ts:`, or
  `first_n_percent:`; `--baseline` CLI flag; allowlists applied uniformly across
  R1–R5.
- **Polish + correlation (Phase 5):** v0.1.0 versioning, README, this changelog,
  `THREAT_MODEL.md`, a runnable `examples/` sample covering all five rules,
  `--timeline` with per-event evidence markers, `--output PATH`, and an optional
  off-by-default cross-rule correlation pass (synthetic **R0** alerts).

### Fixed

- **FP-1.1:** removed the non-deterministic file-mtime year fallback in the
  syslog parser. Year-less syslog timestamps now require `ingest.log_year` and
  fail loudly otherwise, making parsing fully deterministic.

### Security / scope

- Defensive analysis only; no offensive capability. No network anywhere —
  GeoIP reads a local `.mmdb` only. No secrets logged.

[0.1.0]: https://example.invalid/logsentry/releases/tag/v0.1.0

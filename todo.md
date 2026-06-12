# Phase 7 — CI + Repo Polish (todo)

- [x] Task 1 — .github/workflows/ci.yml: push+PR; 3.11–3.14 matrix (ruff+mypy+pytest); no-geo job
- [x] Task 2 — 3.11 floor PROVEN in-sandbox via uv (real Python 3.11.15, 112 tests pass)
- [x] Task 3 — LICENSE (MIT) + pyproject metadata (license, readme, geo/dev extras, classifiers)
- [x] Task 4 — Makefile (lint/type/test/check) — make check green
- [x] Task 5 — README badges (CI, license, Python) — no other change
- [x] Task 6 — ci.yml YAML validated (pyyaml; actionlint unavailable in sandbox)

## Verification

- [x] ruff / mypy --strict / pytest green; make check green
- [x] NO source/detector change; goldens byte-identical to HEAD
- [x] geoip2 optional (absent in dev venv, suite still green); only in geo.py; no runtime network

## Done — repo review-ready at v0.2.0 with CI

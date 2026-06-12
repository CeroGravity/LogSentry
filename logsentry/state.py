"""Persistent R5 baseline state (opt-in).

A small JSON file mapping ``username -> sorted list of known source IPs``. Loads
are tolerant (missing file -> empty); writes are atomic (temp file + rename) and
deterministic (``sort_keys=True``, sorted IP lists). No network; local file only.

The state file holds usernames and IP addresses (no secrets); protect it like
the logs it is derived from.
"""

from __future__ import annotations

import json
import os
from pathlib import Path


def load_state(path: str | Path) -> dict[str, set[str]]:
    """Load per-user known-IP sets from ``path``; missing file -> empty."""
    p = Path(path)
    if not p.is_file():
        return {}
    raw = json.loads(p.read_text(encoding="utf-8"))
    state: dict[str, set[str]] = {}
    for user, ips in raw.items():
        state[str(user)] = {str(ip) for ip in ips}
    return state


def save_state(path: str | Path, known: dict[str, set[str]]) -> None:
    """Atomically write per-user known-IP sets to ``path`` (deterministic).

    IP lists and user keys are sorted; the write goes to a temp file in the same
    directory and is renamed into place so readers never see a partial file.
    """
    p = Path(path)
    serializable = {user: sorted(ips) for user, ips in known.items()}
    text = json.dumps(serializable, sort_keys=True, indent=2) + "\n"
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, p)

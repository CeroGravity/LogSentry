"""Deterministic identity helpers.

A single fixed hash algorithm (SHA-1, truncated) is used for all IDs so that
identical inputs always yield identical IDs across runs and machines. These
helpers do no I/O and never read the wall clock.
"""

from __future__ import annotations

import hashlib

# Length, in hex characters, of truncated IDs. 16 hex chars = 64 bits, which
# is ample for collision avoidance at log scale while staying readable.
_ID_LEN = 16

# Field separator chosen to be unlikely to appear in canonical field values,
# keeping the joined string injective for typical inputs.
_SEP = "\x1f"


def _digest(parts: list[str]) -> str:
    """Return a truncated, fixed-algorithm hex digest of ``parts``.

    Parts are joined with a control-character separator so that distinct
    field boundaries do not collide (e.g. ``["a", "bc"]`` vs ``["ab", "c"]``).
    """
    joined = _SEP.join(parts)
    full = hashlib.sha1(joined.encode("utf-8")).hexdigest()
    return full[:_ID_LEN]


def event_id(source_file: str, line_no: int, raw: str) -> str:
    """Deterministic event ID.

    Derived from the originating ``source_file``, ``line_no`` and the ``raw``
    log line. Same input always produces the same ID.
    """
    return _digest([source_file, str(line_no), raw])


def alert_id(
    rule_id: str,
    dedup_key: str,
    time_range: tuple[str, str],
    entities: tuple[str, ...],
) -> str:
    """Deterministic alert ID from canonical alert fields.

    ``time_range`` is the ISO-8601 start/end pair and ``entities`` is the
    ordered tuple of involved entities; both are part of the alert's
    canonical identity.
    """
    parts = [rule_id, dedup_key, time_range[0], time_range[1], *entities]
    return _digest(parts)

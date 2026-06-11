"""Deterministic scoring and ranking for alerts.

All scoring is integer math with documented formulas; ranking uses an explicit,
fully stable sort key. No wall-clock, no randomness.
"""

from __future__ import annotations

from .models import Alert, Severity

# Base score per severity level.
SEVERITY_BASE: dict[Severity, int] = {
    Severity.INFO: 10,
    Severity.LOW: 30,
    Severity.MEDIUM: 50,
    Severity.HIGH: 70,
    Severity.CRITICAL: 90,
}


def _clamp(value: int, low: int, high: int) -> int:
    """Clamp ``value`` into the inclusive range ``[low, high]``."""
    return max(low, min(high, value))


def score_r1(count: int, distinct_users: int, min_failures: int) -> int:
    """R1 brute-force burst score.

    ``score = clamp(70 + min(20, 5*((count - N)//N))
                       + min(10, 2*(distinct_users - 1)), 0, 100)``
    where ``N = min_failures``.
    """
    n = min_failures
    over = 5 * ((count - n) // n) if n > 0 else 0
    users_bonus = 2 * (distinct_users - 1)
    return _clamp(70 + min(20, over) + min(10, users_bonus), 0, 100)


def score_r2(preceding_failures: int, min_preceding_failures: int) -> int:
    """R2 failed-then-success score.

    ``score = clamp(90 + min(10, 2*(preceding_failures - M)), 0, 100)``
    where ``M = min_preceding_failures``.
    """
    m = min_preceding_failures
    return _clamp(90 + min(10, 2 * (preceding_failures - m)), 0, 100)


def rank_key(alert: Alert) -> tuple[float, int, str, str, str]:
    """Ascending sort key: ``(-score, -severity_int, start, rule_id, dedup_key)``.

    Higher score and higher severity sort first (via negation); ties broken by
    earliest start time, then rule_id, then dedup_key — fully deterministic.
    """
    return (
        -alert.score,
        -alert.severity.value,
        alert.time_range[0].isoformat(),
        alert.rule_id,
        alert.dedup_key,
    )


def rank_alerts(alerts: tuple[Alert, ...]) -> tuple[Alert, ...]:
    """Return ``alerts`` ranked by :func:`rank_key` (stable)."""
    return tuple(sorted(alerts, key=rank_key))

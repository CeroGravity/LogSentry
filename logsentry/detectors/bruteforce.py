"""R1 brute_force_burst — rapid repeated failed auths from a source.

Deterministic burst detection: failures are grouped per key, the failures that
participate in any dense window are marked "alerting", consecutive alerting
failures are coalesced into bursts, and one HIGH alert is emitted per burst.
Pure: no I/O, no wall-clock.
"""

from __future__ import annotations

from datetime import datetime

from .. import ids
from ..models import Alert, LoginEvent, Outcome, Severity
from ..protocols import AnalysisContext
from ..scoring import score_r1
from ._common import is_allowlisted

_FAILURE_OUTCOMES = frozenset({Outcome.FAILURE, Outcome.INVALID_USER})


def _sort_key(ev: LoginEvent) -> tuple[datetime, int]:
    return (ev.timestamp, ev.line_no)


class BruteForceDetector:
    """Detect bursts of failed authentications from a source."""

    name = "R1"
    rule_id = "R1"

    def __init__(self, config: AnalysisContext | None = None) -> None:
        # Config is read from the context at analyze time; ctor kept simple.
        pass

    def analyze(
        self, events: list[LoginEvent], ctx: AnalysisContext
    ) -> list[Alert]:
        cfg = ctx.config.r1
        allowlists = ctx.config.allowlists

        # Group failures by key, preserving determinism via explicit sort later.
        groups: dict[tuple[str, ...], list[LoginEvent]] = {}
        for ev in events:
            if ev.outcome not in _FAILURE_OUTCOMES:
                continue
            if ev.source_ip is None or is_allowlisted(ev, allowlists):
                continue
            key = self._key(ev, cfg.per_user)
            groups.setdefault(key, []).append(ev)

        alerts: list[Alert] = []
        # Sort keys for deterministic alert ordering before ranking.
        for key in sorted(groups):
            failures = sorted(groups[key], key=_sort_key)
            for burst in self._bursts(failures, cfg.window_seconds, cfg.min_failures):
                alerts.append(self._make_alert(burst, cfg.min_failures))
        return alerts

    def _key(self, ev: LoginEvent, per_user: bool) -> tuple[str, ...]:
        ip = ev.source_ip or ""
        if per_user:
            return (ip, ev.username or "")
        return (ip,)

    def _bursts(
        self, failures: list[LoginEvent], window_seconds: int, min_failures: int
    ) -> list[list[LoginEvent]]:
        """Return coalesced bursts of alerting failures for one key.

        A failure is *alerting* if it lies in some ``window_seconds`` span
        containing >= ``min_failures`` failures. Alerting failures are then
        coalesced; a new burst starts when the gap between consecutive alerting
        failures exceeds ``window_seconds``.
        """
        n = len(failures)
        if n < min_failures or min_failures <= 0:
            return []

        ts = [f.timestamp.timestamp() for f in failures]
        alerting = [False] * n
        # Two-pointer: for each start i, extend j while within the window; if
        # the span [i, j] holds >= min_failures, mark all of them alerting.
        j = 0
        for i in range(n):
            if j < i:
                j = i
            while j + 1 < n and ts[j + 1] - ts[i] <= window_seconds:
                j += 1
            if (j - i + 1) >= min_failures:
                for k in range(i, j + 1):
                    alerting[k] = True

        # Coalesce consecutive alerting failures; split on gap > window_seconds.
        bursts: list[list[LoginEvent]] = []
        current: list[LoginEvent] = []
        prev_ts: float | None = None
        for idx in range(n):
            if not alerting[idx]:
                continue
            if current and prev_ts is not None and ts[idx] - prev_ts > window_seconds:
                bursts.append(current)
                current = []
            current.append(failures[idx])
            prev_ts = ts[idx]
        if current:
            bursts.append(current)
        return bursts

    def _make_alert(self, burst: list[LoginEvent], min_failures: int) -> Alert:
        ip = burst[0].source_ip or ""
        users = sorted({ev.username for ev in burst if ev.username is not None})
        count = len(burst)
        # entities: distinct usernames sorted, then the ip (last). The report
        # layer reconstructs the structured object from this convention.
        entities = (*users, ip)
        evidence = tuple(ev.event_id for ev in burst)
        start, end = burst[0].timestamp, burst[-1].timestamp
        time_range = (start, end)
        dedup_key = f"R1:{ip}:{start.isoformat()}:{end.isoformat()}"
        score = score_r1(count, len(users), min_failures)
        users_label = ", ".join(users) if users else "(none)"
        description = (
            f"{count} failed authentications from {ip} "
            f"targeting {len(users)} user(s): {users_label}"
        )
        alert_id = ids.alert_id(
            self.rule_id, dedup_key, (start.isoformat(), end.isoformat()), entities
        )
        return Alert(
            alert_id=alert_id,
            rule_id=self.rule_id,
            title="Brute-force burst",
            severity=Severity.HIGH,
            score=score,
            time_range=time_range,
            entities=entities,
            evidence=evidence,
            description=description,
            dedup_key=dedup_key,
        )

"""R2 failed_then_success — failures then a success for the same entity.

For each qualifying SUCCESS, count the preceding failures for the same key
within ``window_seconds``; if there are >= ``min_preceding_failures``, emit one
CRITICAL alert. Pure: no I/O, no wall-clock.
"""

from __future__ import annotations

from datetime import datetime

from .. import ids
from ..models import Alert, LoginEvent, Outcome, Severity
from ..protocols import AnalysisContext
from ..scoring import score_r2

_FAILURE_OUTCOMES = frozenset({Outcome.FAILURE, Outcome.INVALID_USER})


def _sort_key(ev: LoginEvent) -> tuple[datetime, int]:
    return (ev.timestamp, ev.line_no)


class FailedThenSuccessDetector:
    """Detect a success preceded by enough recent failures for one entity."""

    name = "R2"
    rule_id = "R2"

    def __init__(self, config: AnalysisContext | None = None) -> None:
        pass

    def analyze(
        self, events: list[LoginEvent], ctx: AnalysisContext
    ) -> list[Alert]:
        cfg = ctx.config.r2
        allow_users = set(ctx.config.allowlists.users)
        allow_ips = set(ctx.config.allowlists.ips)

        groups: dict[tuple[str, ...], list[LoginEvent]] = {}
        for ev in events:
            if ev.username is None or ev.username in allow_users:
                continue
            if ev.source_ip is not None and ev.source_ip in allow_ips:
                continue
            key = self._key(ev, cfg.require_same_source_ip)
            groups.setdefault(key, []).append(ev)

        alerts: list[Alert] = []
        for key in sorted(groups):
            ordered = sorted(groups[key], key=_sort_key)
            alerts.extend(
                self._scan(ordered, cfg.window_seconds, cfg.min_preceding_failures)
            )
        return alerts

    def _key(self, ev: LoginEvent, same_ip: bool) -> tuple[str, ...]:
        user = ev.username or ""
        if same_ip:
            return (user, ev.source_ip or "")
        return (user,)

    def _scan(
        self,
        ordered: list[LoginEvent],
        window_seconds: int,
        min_preceding: int,
    ) -> list[Alert]:
        """Emit one alert per success with enough in-window preceding failures."""
        alerts: list[Alert] = []
        for i, ev in enumerate(ordered):
            if ev.outcome is not Outcome.SUCCESS:
                continue
            success_ts = ev.timestamp.timestamp()
            # Preceding failures within the window, in chronological order.
            preceding: list[LoginEvent] = []
            for prior in ordered[:i]:
                if prior.outcome not in _FAILURE_OUTCOMES:
                    continue
                if success_ts - prior.timestamp.timestamp() <= window_seconds:
                    preceding.append(prior)
            if len(preceding) >= min_preceding:
                alerts.append(self._make_alert(preceding, ev, min_preceding))
        return alerts

    def _make_alert(
        self, preceding: list[LoginEvent], success: LoginEvent, min_preceding: int
    ) -> Alert:
        username = success.username or ""
        source_ip = success.source_ip or ""
        entities = (username, source_ip)
        evidence = tuple(ev.event_id for ev in preceding) + (success.event_id,)
        start = preceding[0].timestamp
        end = success.timestamp
        time_range = (start, end)
        count = len(preceding)
        dedup_key = f"R2:{username}:{source_ip}:{success.event_id}"
        score = score_r2(count, min_preceding)
        description = (
            f"{count} failed attempt(s) for {username} from {source_ip} "
            f"followed by a successful login"
        )
        alert_id = ids.alert_id(
            self.rule_id, dedup_key, (start.isoformat(), end.isoformat()), entities
        )
        return Alert(
            alert_id=alert_id,
            rule_id=self.rule_id,
            title="Failed-then-success",
            severity=Severity.CRITICAL,
            score=score,
            time_range=time_range,
            entities=entities,
            evidence=evidence,
            description=description,
            dedup_key=dedup_key,
        )

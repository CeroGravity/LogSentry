"""R5 new_source_ip_per_user — first auth from an unseen IP per user.

The user's known-IP set is seeded from ``ctx.baseline_events``; analyzed events
are then walked in stream order. A user whose baseline known-set is initially
empty is never alerted (learn silently — avoids first-run flooding). The first
analyzed event from an IP not in the set raises one LOW alert, after which the
IP is added so repeats do not re-alert.
"""

from __future__ import annotations

from .. import ids
from ..models import Alert, LoginEvent, NewSourceIPDetail, Outcome, Severity
from ..protocols import AnalysisContext
from ..scoring import score_r5
from ._common import is_allowlisted


class NewSourceIPDetector:
    """Detect the first authentication from an unseen IP per user vs baseline."""

    name = "R5"
    rule_id = "R5"

    def __init__(self, config: AnalysisContext | None = None) -> None:
        pass

    def analyze(
        self, events: list[LoginEvent], ctx: AnalysisContext
    ) -> list[Alert]:
        cfg = ctx.config.r5
        allowlists = ctx.config.allowlists

        # Seed per-user known-IP sets from baseline (successes only unless
        # only_success=false). Track which users had a non-empty baseline.
        known: dict[str, set[str]] = {}
        for ev in ctx.baseline_events:
            if not self._considered(ev, cfg.only_success):
                continue
            known.setdefault(ev.username or "", set()).add(ev.source_ip or "")
        seeded_users = {u for u, ips in known.items() if ips}

        alerts: list[Alert] = []
        for ev in events:
            if not self._considered(ev, cfg.only_success):
                continue
            if is_allowlisted(ev, allowlists):
                continue
            user = ev.username or ""
            ip = ev.source_ip or ""
            # Users with an initially-empty baseline are learned silently.
            if user not in seeded_users:
                continue
            user_known = known.setdefault(user, set())
            if ip in user_known:
                continue
            known_count = len(user_known)
            user_known.add(ip)  # so a repeat of this IP won't re-alert
            alerts.append(self._make_alert(ev, user, ip, known_count))
        return alerts

    @staticmethod
    def _considered(ev: LoginEvent, only_success: bool) -> bool:
        if ev.username is None or ev.source_ip is None:
            return False
        return ev.outcome is Outcome.SUCCESS or not only_success

    def _make_alert(
        self, ev: LoginEvent, user: str, ip: str, known_count: int
    ) -> Alert:
        entities = (user, ip)
        evidence = (ev.event_id,)
        ts = ev.timestamp
        detail = NewSourceIPDetail(new_ip=ip, known_ip_count=known_count)
        dedup_key = f"R5:{user}:{ip}"
        score = score_r5()
        description = (
            f"{user} authenticated from a new source IP {ip} "
            f"(not among {known_count} known IP(s))"
        )
        alert_id = ids.alert_id(
            self.rule_id, dedup_key, (ts.isoformat(), ts.isoformat()), entities
        )
        return Alert(
            alert_id=alert_id,
            rule_id=self.rule_id,
            title="New source IP",
            severity=Severity.LOW,
            score=score,
            time_range=(ts, ts),
            entities=entities,
            evidence=evidence,
            description=description,
            dedup_key=dedup_key,
            details=detail,
        )

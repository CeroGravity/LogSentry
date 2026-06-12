"""R4 off_hours_access — successful login outside configured business hours.

Each (success) event is converted to the configured timezone; off-hours events
are then collapsed per ``(username, local_date)`` into ONE MEDIUM alert. Pure:
no I/O, no wall-clock (tz conversion uses zoneinfo on the event's own ts).
"""

from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo

from .. import ids
from ..config import R4OffHours
from ..models import Alert, LoginEvent, OffHoursDetail, Outcome, Severity
from ..protocols import AnalysisContext
from ..scoring import score_r4
from ._common import is_allowlisted

_WEEKDAY_NAMES = (
    "Monday", "Tuesday", "Wednesday", "Thursday",
    "Friday", "Saturday", "Sunday",
)


def _sort_key(ev: LoginEvent) -> tuple[datetime, int]:
    return (ev.timestamp, ev.line_no)


def _business_window_label(cfg: R4OffHours) -> str:
    """Human-readable business window, e.g. 'Mon-Fri 08:00-18:00 UTC'."""
    short = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
    days = ",".join(short[d] for d in cfg.business_days)
    start = cfg.business_start.strftime("%H:%M")
    end = cfg.business_end.strftime("%H:%M")
    return f"{days} {start}-{end} {cfg.timezone}"


class OffHoursDetector:
    """Detect successful logins outside configured business hours."""

    name = "R4"
    rule_id = "R4"

    def analyze(
        self, events: list[LoginEvent], ctx: AnalysisContext
    ) -> list[Alert]:
        cfg = ctx.config.r4
        allowlists = ctx.config.allowlists
        tz = ZoneInfo(cfg.timezone)
        window = _business_window_label(cfg)
        business_days = set(cfg.business_days)

        # Group off-hours events per (username, local_date).
        groups: dict[tuple[str, str], list[tuple[LoginEvent, datetime]]] = {}
        for ev in events:
            if is_allowlisted(ev, allowlists):
                continue
            if ev.outcome is not Outcome.SUCCESS and cfg.only_success:
                continue
            local = ev.timestamp.astimezone(tz)
            non_business_day = local.weekday() not in business_days
            outside_window = not (
                cfg.business_start <= local.time() < cfg.business_end
            )
            if not (non_business_day or outside_window):
                continue
            key = (ev.username or "", local.date().isoformat())
            groups.setdefault(key, []).append((ev, local))

        alerts: list[Alert] = []
        for key in sorted(groups):
            members = sorted(groups[key], key=lambda pair: _sort_key(pair[0]))
            alerts.append(self._make_alert(key, members, window, business_days))
        return alerts

    def _make_alert(
        self,
        key: tuple[str, str],
        members: list[tuple[LoginEvent, datetime]],
        window: str,
        business_days: set[int],
    ) -> Alert:
        username, local_date = key
        first_ev, first_local = members[0]
        last_ev, last_local = members[-1]
        source_ip = first_ev.source_ip or ""
        entities = (username, source_ip)
        evidence = tuple(ev.event_id for ev, _ in members)
        count = len(members)
        # All members share one local date -> one weekday -> consistent flag.
        non_business_day = first_local.weekday() not in business_days
        weekday = _WEEKDAY_NAMES[first_local.weekday()]
        detail = OffHoursDetail(
            local_time=first_local.isoformat(),
            weekday=weekday,
            business_window=window,
            non_business_day=non_business_day,
            event_count=count,
            last_local_time=last_local.isoformat(),
        )
        dedup_key = f"R4:{username}:{local_date}"
        score = score_r4(non_business_day)
        reason = "non-business day" if non_business_day else "outside hours"
        description = (
            f"{username} logged in from {source_ip} at {first_local.isoformat()} "
            f"({weekday}, {reason})"
        )
        if count > 1:
            description += f" ({count} logins)"
        start, end = first_ev.timestamp, last_ev.timestamp
        alert_id = ids.alert_id(
            self.rule_id, dedup_key, (start.isoformat(), end.isoformat()), entities
        )
        return Alert(
            alert_id=alert_id,
            rule_id=self.rule_id,
            title="Off-hours access",
            severity=Severity.MEDIUM,
            score=score,
            time_range=(start, end),
            entities=entities,
            evidence=evidence,
            description=description,
            dedup_key=dedup_key,
            details=detail,
        )

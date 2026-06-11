"""R4 off_hours_access — successful login outside configured business hours.

Each (success) event is converted to the configured timezone; if it falls on a
non-business day or outside the business window it raises one MEDIUM alert.
Pure: no I/O, no wall-clock (tz conversion uses zoneinfo on the event's own ts).
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

    def __init__(self, config: AnalysisContext | None = None) -> None:
        pass

    def analyze(
        self, events: list[LoginEvent], ctx: AnalysisContext
    ) -> list[Alert]:
        cfg = ctx.config.r4
        allowlists = ctx.config.allowlists
        tz = ZoneInfo(cfg.timezone)
        window = _business_window_label(cfg)
        business_days = set(cfg.business_days)

        alerts: list[Alert] = []
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
            alerts.append(
                self._make_alert(ev, local, non_business_day, window)
            )
        return alerts

    def _make_alert(
        self,
        ev: LoginEvent,
        local: datetime,
        non_business_day: bool,
        window: str,
    ) -> Alert:
        username = ev.username or ""
        source_ip = ev.source_ip or ""
        entities = (username, source_ip)
        evidence = (ev.event_id,)
        ts = ev.timestamp
        weekday = _WEEKDAY_NAMES[local.weekday()]
        detail = OffHoursDetail(
            local_time=local.isoformat(),
            weekday=weekday,
            business_window=window,
            non_business_day=non_business_day,
        )
        dedup_key = f"R4:{username}:{source_ip}:{ev.event_id}"
        score = score_r4(non_business_day)
        reason = "non-business day" if non_business_day else "outside hours"
        description = (
            f"{username} logged in from {source_ip} at {local.isoformat()} "
            f"({weekday}, {reason})"
        )
        alert_id = ids.alert_id(
            self.rule_id, dedup_key, (ts.isoformat(), ts.isoformat()), entities
        )
        return Alert(
            alert_id=alert_id,
            rule_id=self.rule_id,
            title="Off-hours access",
            severity=Severity.MEDIUM,
            score=score,
            time_range=(ts, ts),
            entities=entities,
            evidence=evidence,
            description=description,
            dedup_key=dedup_key,
            details=detail,
        )

"""R3 impossible_travel — same user, two locations too far apart too fast.

For each user, events are first filtered to those with a real resolved location
(public, resolver returned coordinates); unresolved/private events are dropped
from the sequence rather than breaking a pair. Consecutive *resolved* events are
then compared: if the implied speed exceeds ``max_kmh`` and the hop is at least
``min_distance_km``, one HIGH alert is emitted per qualifying pair. Pure: no I/O
(resolver may read a local DB), no wall-clock.
"""

from __future__ import annotations

from datetime import datetime

from .. import ids
from ..geo import haversine
from ..models import (
    Alert,
    GeoDetail,
    GeoLocation,
    GeoPoint,
    LoginEvent,
    Outcome,
    Severity,
)
from ..protocols import AnalysisContext
from ..scoring import score_r3
from ._common import is_allowlisted


def _sort_key(ev: LoginEvent) -> tuple[datetime, int]:
    return (ev.timestamp, ev.line_no)


def _geo_point(loc: GeoLocation) -> GeoPoint:
    return GeoPoint(
        ip=loc.ip, lat=loc.lat, lon=loc.lon, country=loc.country, city=loc.city
    )


class ImpossibleTravelDetector:
    """Detect physically impossible movement between consecutive logins."""

    name = "R3"
    rule_id = "R3"

    def analyze(
        self, events: list[LoginEvent], ctx: AnalysisContext
    ) -> list[Alert]:
        cfg = ctx.config.r3
        resolver = ctx.geo_resolver
        allowlists = ctx.config.allowlists

        groups: dict[str, list[LoginEvent]] = {}
        for ev in events:
            if ev.username is None or ev.source_ip is None:
                continue
            if is_allowlisted(ev, allowlists):
                continue
            if ev.outcome is not Outcome.SUCCESS and not cfg.consider_failures:
                continue
            groups.setdefault(ev.username, []).append(ev)

        alerts: list[Alert] = []
        for username in sorted(groups):
            ordered = sorted(groups[username], key=_sort_key)
            # Sandwich-gap fix: filter to events with a real resolved location
            # FIRST, then pair consecutive resolved events. An unresolved or
            # private event between two resolved ones no longer breaks the pair.
            resolved: list[tuple[LoginEvent, GeoLocation]] = []
            for ev in ordered:
                loc = resolver.resolve(ev.source_ip or "")
                if self._resolved(loc):
                    assert loc is not None
                    resolved.append((ev, loc))
            for (prev, loc_from), (curr, loc_to) in zip(
                resolved, resolved[1:], strict=False
            ):
                alert = self._evaluate(
                    username, prev, curr, loc_from, loc_to,
                    cfg.max_kmh, cfg.min_distance_km,
                )
                if alert is not None:
                    alerts.append(alert)
        return alerts

    def _evaluate(
        self,
        username: str,
        prev: LoginEvent,
        curr: LoginEvent,
        loc_from: GeoLocation,
        loc_to: GeoLocation,
        max_kmh: int,
        min_distance_km: int,
    ) -> Alert | None:
        ip_from = prev.source_ip or ""
        ip_to = curr.source_ip or ""
        assert loc_from.lat is not None and loc_from.lon is not None
        assert loc_to.lat is not None and loc_to.lon is not None

        distance_km = haversine(
            loc_from.lat, loc_from.lon, loc_to.lat, loc_to.lon
        )
        delta_seconds = (curr.timestamp - prev.timestamp).total_seconds()
        if delta_seconds <= 0:
            # Non-positive elapsed time: any nonzero distance is instantaneous
            # travel -> treat as impossible (very-high implied speed). A zero
            # distance (same place) still cannot qualify (min_distance guard).
            implied_kmh_float = float("inf") if distance_km > 0 else 0.0
        else:
            implied_kmh_float = distance_km / (delta_seconds / 3600.0)

        if not (implied_kmh_float > max_kmh and distance_km >= min_distance_km):
            return None

        implied_kmh = (
            10 ** 9 if implied_kmh_float == float("inf")
            else int(implied_kmh_float)
        )
        delta_int = int(delta_seconds)
        detail = GeoDetail(
            src=_geo_point(loc_from),
            dst=_geo_point(loc_to),
            distance_km=distance_km,
            delta_seconds=delta_int,
            implied_kmh=implied_kmh,
        )
        return self._make_alert(username, prev, curr, ip_from, ip_to, detail, max_kmh)

    @staticmethod
    def _resolved(loc: GeoLocation | None) -> bool:
        return (
            loc is not None
            and not loc.is_private
            and loc.lat is not None
            and loc.lon is not None
        )

    def _make_alert(
        self,
        username: str,
        prev: LoginEvent,
        curr: LoginEvent,
        ip_from: str,
        ip_to: str,
        detail: GeoDetail,
        max_kmh: int,
    ) -> Alert:
        start, end = prev.timestamp, curr.timestamp
        entities = (username, ip_from, ip_to)
        evidence = (prev.event_id, curr.event_id)
        dedup_key = f"R3:{username}:{prev.event_id}:{curr.event_id}"
        score = score_r3(detail.implied_kmh, max_kmh)
        description = (
            f"{username} seen at {ip_from} then {ip_to}: "
            f"{detail.distance_km:.1f} km in {detail.delta_seconds}s "
            f"(~{detail.implied_kmh} km/h)"
        )
        alert_id = ids.alert_id(
            self.rule_id, dedup_key, (start.isoformat(), end.isoformat()), entities
        )
        return Alert(
            alert_id=alert_id,
            rule_id=self.rule_id,
            title="Impossible travel",
            severity=Severity.HIGH,
            score=score,
            time_range=(start, end),
            entities=entities,
            evidence=evidence,
            description=description,
            dedup_key=dedup_key,
            details=detail,
        )

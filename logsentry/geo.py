"""Geo resolvers. Phase 2 ships only :class:`NullResolver`.

``NullResolver`` resolves nothing — a deterministic, offline placeholder so the
:class:`~logsentry.protocols.AnalysisContext` always has a resolver. Real geo
(static / MaxMind) lands in a later phase. No network, no deps.
"""

from __future__ import annotations

from .models import GeoLocation


class NullResolver:
    """A :class:`~logsentry.protocols.GeoResolver` that resolves nothing."""

    def resolve(self, ip: str) -> GeoLocation | None:
        """Always return ``None`` — no geo data available."""
        return None

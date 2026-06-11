"""Structural protocols and the analysis context for LogSentry.

Defines the contracts detectors and geo resolvers must satisfy. Phase 0
provides protocol definitions and the immutable :class:`AnalysisContext`
only — no concrete implementations.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, tzinfo
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from .config import Config
    from .models import Alert, GeoLocation, LoginEvent


@runtime_checkable
class GeoResolver(Protocol):
    """Resolves an IP address to a :class:`~logsentry.models.GeoLocation`.

    Implementations must be deterministic and side-effect free for a given
    input. Returns ``None`` when no location can be determined.
    """

    def resolve(self, ip: str) -> GeoLocation | None:
        """Resolve ``ip`` to a location, or ``None`` if unknown."""
        ...


@runtime_checkable
class Detector(Protocol):
    """A single detection rule.

    ``name`` is a stable identifier (e.g. ``"R1"``). ``analyze`` is pure:
    given events and a context it returns alerts without mutating either.
    """

    @property
    def name(self) -> str:
        """Stable detector identifier."""
        ...

    def analyze(
        self,
        events: list[LoginEvent],
        ctx: AnalysisContext,
    ) -> list[Alert]:
        """Analyze ``events`` within ``ctx`` and return any alerts."""
        ...


@dataclass(frozen=True)
class AnalysisContext:
    """Immutable context passed to every detector.

    ``now`` is the injected clock — the single source of "current time" so
    that analysis output is fully deterministic. ``tz`` is the explicit
    analysis timezone; never the implicit system timezone.
    """

    config: Config
    baseline_events: tuple[LoginEvent, ...]
    geo_resolver: GeoResolver
    now: datetime
    tz: tzinfo

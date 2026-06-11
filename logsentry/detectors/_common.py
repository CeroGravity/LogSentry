"""Shared detector helpers.

A single allowlist predicate applied uniformly across R1–R5 so suppression
semantics are identical everywhere. Inert when no allowlists are configured.
"""

from __future__ import annotations

from ..config import Allowlists
from ..models import LoginEvent


def is_allowlisted(event: LoginEvent, allowlists: Allowlists) -> bool:
    """True if the event's source IP or username is allowlisted."""
    if event.source_ip is not None and event.source_ip in allowlists.ips:
        return True
    return event.username is not None and event.username in allowlists.users

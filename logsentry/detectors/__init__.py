"""Detection rules for LogSentry.

Ships R1 (brute_force_burst), R2 (failed_then_success), R3 (impossible_travel),
R4 (off_hours_access) and R5 (new_source_ip_per_user).
"""

from __future__ import annotations

from .bruteforce import BruteForceDetector
from .failsucc import FailedThenSuccessDetector
from .impossibletravel import ImpossibleTravelDetector
from .newsourceip import NewSourceIPDetector
from .offhours import OffHoursDetector

__all__ = [
    "BruteForceDetector",
    "FailedThenSuccessDetector",
    "ImpossibleTravelDetector",
    "NewSourceIPDetector",
    "OffHoursDetector",
]

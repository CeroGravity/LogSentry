"""Detection rules for LogSentry.

Phase 2 ships R1 (brute_force_burst) and R2 (failed_then_success). Other rules
remain stubs until their phases.
"""

from __future__ import annotations

from .bruteforce import BruteForceDetector
from .failsucc import FailedThenSuccessDetector

__all__ = ["BruteForceDetector", "FailedThenSuccessDetector"]

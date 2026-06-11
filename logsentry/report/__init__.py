"""Deterministic report rendering (JSON and text).

Both renderers take the analysis result plus the injected ``now`` and produce
byte-stable output for fixed inputs.
"""

from __future__ import annotations

from .json_report import render_json
from .text_report import render_text

__all__ = ["render_json", "render_text"]

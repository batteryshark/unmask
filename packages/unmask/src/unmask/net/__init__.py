"""Fetch-only network: pull referenced remote code as evidence, never execute it.

Off unless the run opts in (``--network fetch-only``). URLs that the target executes
are fetched under an SSRF guard and rescanned statically, so ``curl … | sh`` droppers
stop being a blind spot. See `guard.classify_url` for the safety gate.
"""

from __future__ import annotations

from unmask.net.fetch import FetchPolicy, FetchResult, fetch
from unmask.net.guard import classify_url
from unmask.net.references import FetchTarget, extract_fetch_targets

__all__ = [
    "FetchPolicy", "FetchResult", "fetch", "classify_url",
    "FetchTarget", "extract_fetch_targets",
]

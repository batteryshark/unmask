"""Find URLs worth fetching: remote code that the target actually runs.

A URL is only interesting as fetchable evidence when the file that references it also
*executes or installs* — the ``curl … | sh`` / ``pip install <url>`` / download-and-eval
shape. A URL in a comment or a docs link has no execution intent and is left alone. The
URL text comes from the ARTF.URL observations the scanner already produced.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Atoms that mean "code from elsewhere gets run/installed here".
_EXEC_INTENT = frozenset({
    "EXEC.SHELL", "EXEC.PROC", "LOAD.EVAL", "LOAD.DYNAMIC", "LOAD.IMPORT",
    "PKGM.INSTALL", "PKGM.BINDOWN",
})
_URL_RE = re.compile(r"https?://[^\s'\"<>)\]}\\]+")


@dataclass(frozen=True)
class FetchTarget:
    url: str
    source_rel: str
    reason: tuple


def extract_fetch_targets(observations, inv=None, *, max_targets: int = 8) -> list[FetchTarget]:
    """URLs referenced in files that also carry execution/install intent, de-duplicated
    and capped. ``inv`` is accepted for symmetry with the other passes but unused —
    everything needed is in the observations."""
    by_path: dict[str, dict] = {}
    for o in observations:
        entry = by_path.setdefault(o.path, {"atoms": set(), "urls": []})
        entry["atoms"].add(o.atom)
        if o.atom == "ARTF.URL" and o.evidence:
            entry["urls"].extend(_URL_RE.findall(str(o.evidence)))

    targets: list[FetchTarget] = []
    seen: set[str] = set()
    for path, entry in by_path.items():
        intent = entry["atoms"] & _EXEC_INTENT
        if not intent:
            continue
        for url in entry["urls"]:
            url = url.rstrip(".,;")
            if url in seen:
                continue
            seen.add(url)
            targets.append(FetchTarget(url=url, source_rel=path, reason=tuple(sorted(intent))))
            if len(targets) >= max_targets:
                return targets
    return targets

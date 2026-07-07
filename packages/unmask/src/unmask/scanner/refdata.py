"""Access to vendored taxonomy reference tables.

Reference tables (file classification, binary magic, benign IPs, popular packages,
…) are meaning owned by the taxonomy, vendored into the wheel under
`taxonomy/vendored/reference/`. The old engine hardcoded these in-module; the
rebuild reads them as data so they refresh with the taxonomy.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

# scanner/refdata.py -> parents[1] == the unmask package root.
_UNMASK_PKG = Path(__file__).resolve().parents[1]


def reference_dir() -> Path:
    return _UNMASK_PKG / "taxonomy" / "vendored" / "reference"


@lru_cache(maxsize=None)
def load_reference(name: str) -> dict | list | None:
    """Load `reference/<name>.json`, or None if it isn't vendored."""
    fp = reference_dir() / f"{name}.json"
    if not fp.is_file():
        return None
    return json.loads(fp.read_text(encoding="utf-8"))

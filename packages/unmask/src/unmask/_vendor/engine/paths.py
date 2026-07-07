"""Locate shared Parallax assets (schemas, taxonomy) without hardcoding paths.

In the current monorepo the schemas live at the repo root in `schemas/`.
After the taxonomy/engine repo split this resolver is the single place that
needs to change.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

_MARKER = os.path.join("schemas", "scan-report.schema.json")
_TAXONOMY_MARKER = os.path.join("signatures", "schema.json")


def find_repo_root(start: Optional[Path] = None) -> Optional[Path]:
    """Walk upward from `start` (or this file) looking for the schemas marker."""
    candidates = []
    if start is not None:
        candidates.append(Path(start).resolve())
    candidates.append(Path(__file__).resolve())
    candidates.append(Path.cwd())
    for c in candidates:
        for d in [c, *c.parents]:
            if (d / _MARKER).is_file():
                return d
    return None


def schemas_dir(start: Optional[Path] = None) -> Optional[Path]:
    root = find_repo_root(start)
    return (root / "schemas") if root else None


def taxonomy_root(start: Optional[Path] = None) -> Optional[Path]:
    """Locate a parallax-taxonomy checkout.

    `PRLX_TAXONOMY_ROOT` is the pinning hook for downstream tools. In the local
    development layout the taxonomy repo is usually a sibling of `parallax`.

    When this engine is vendored (as in parallax-goalpacks), the taxonomy
    signatures it needs are bundled alongside this package under
    `taxonomy/` (next to this file). That bundled copy is the final fallback,
    so the vendored engine is self-contained without any env being set.
    """
    env = os.environ.get("PRLX_TAXONOMY_ROOT")
    if env:
        root = Path(env).expanduser().resolve()
        return root if (root / _TAXONOMY_MARKER).is_file() else None

    repo = find_repo_root(start)
    candidates = []
    if repo is not None:
        candidates.extend([repo.parent / "parallax-taxonomy", repo / "parallax-taxonomy"])
    candidates.extend([Path.cwd() / "parallax-taxonomy", Path.cwd().parent / "parallax-taxonomy"])
    # Bundled fallback: a `taxonomy/` dir vendored next to this package.
    candidates.append(Path(__file__).resolve().parent / "taxonomy")
    for candidate in candidates:
        try:
            root = candidate.resolve()
        except OSError:
            continue
        if (root / _TAXONOMY_MARKER).is_file():
            return root
    return None

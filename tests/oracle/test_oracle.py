"""Differential oracle gate: the active scanner must not under-detect vs the
frozen old-engine goldens.

Today the active backend IS the vendored old engine, so this passes trivially.
Its purpose is the rebuild: as native `unmask.scanner` slices replace the vendored
backend, this test fails loudly the moment the new code drops an atom, a BP-*
composition, or weakens a disposition the old engine produced — turning silent
under-detection into a red test. Where the old engine was wrong, update the golden
(via `capture.py`) with a recorded reason; never weaken the assertion.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

ORACLE_DIR = Path(__file__).resolve().parent
GOLDEN = ORACLE_DIR / "golden"
REPO_ROOT = ORACLE_DIR.parents[1]

CORPUS = [
    ("evil-npm", "tests/fixtures/evil-npm"),
    ("benign-pkg", "tests/oracle/fixtures/benign-pkg"),
    ("py-curlpipe", "tests/oracle/fixtures/py-curlpipe"),
    ("obf-js", "tests/oracle/fixtures/obf-js"),
]


def _active_scan(target: str):
    """Run the currently-active scanner backend. Repoint here when the native
    scanner replaces the transitional vendored one."""
    from unmask.scanner import ParallaxScanner
    return ParallaxScanner().scan(target)


def _golden(name: str, part: str):
    return json.loads((GOLDEN / name / f"{part}.json").read_text(encoding="utf-8"))


def _scanner_available() -> bool:
    try:
        from unmask.scanner import ParallaxScanner
        ParallaxScanner()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _scanner_available(), reason="scanner backend unavailable")


@pytest.mark.parametrize("name,target", CORPUS, ids=[c[0] for c in CORPUS])
def test_no_under_detection(name, target):
    result = _active_scan(str((REPO_ROOT / target).resolve()))

    golden_atoms = {o["atom"] for o in _golden(name, "observations")}
    current_atoms = {o.get("atom") for o in result.observations}
    missing_atoms = golden_atoms - current_atoms
    assert not missing_atoms, f"{name}: dropped atoms vs oracle: {sorted(missing_atoms)}"

    golden_assess = _golden(name, "assessment")
    golden_comps = set((golden_assess.get("summary") or {}).get("compositions") or [])
    current_comps = {f.get("_composition") for f in result.findings if f.get("_composition")}
    missing_comps = golden_comps - current_comps
    assert not missing_comps, f"{name}: dropped BP-* compositions vs oracle: {sorted(missing_comps)}"

    golden_disp = (golden_assess.get("disposition") or {}).get("recommendation")
    current_disp = (result.assessment.get("disposition") or {}).get("recommendation")
    # Never weaker than the oracle (clear < review < quarantine).
    rank = {"clear": 0, "review": 1, "quarantine": 2, None: -1}
    assert rank.get(current_disp, -1) >= rank.get(golden_disp, -1), (
        f"{name}: disposition weakened {golden_disp} -> {current_disp}"
    )

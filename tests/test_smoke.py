"""End-to-end smoke test over the bundled evil-npm fixture.

The scanner (engine + mcd_lens) and taxonomy signatures are vendored into the
wheel, so this resolves with nothing set — no UNMASK_SCANNER_ROOT, no sibling
parallax-goalpacks/parallax-taxonomy checkout. The test runs by default.
"""

from __future__ import annotations

import json
from pathlib import Path

FIXTURE = Path(__file__).parent / "fixtures" / "evil-npm"


def test_evil_npm_quarantine(tmp_path):
    from unmask import MCDConfig, run_mcd

    result = run_mcd(str(FIXTURE), MCDConfig(storage_root=str(tmp_path / ".mcd")))

    assert result.status == "completed"
    assert result.disposition == "quarantine"
    assert result.finding_count >= 1

    report = json.loads(Path(result.report_paths["json"]).read_text())
    # unmask sections are added without clobbering the assessment.
    assert report["ledger"]["runId"] == result.run_id
    assert "coverage" in report["ledger"]
    # Don't couple the test to whether unmask-re happens to be installed here.
    assert isinstance(report["toolchain"]["reProvidersInstalled"], bool)


def test_tree_is_bounded():
    from unmask.inventory.tree import build_tree

    tree = build_tree(FIXTURE, max_entries=10)
    assert tree.summary["files"] >= 1
    assert "package.json" in tree.text

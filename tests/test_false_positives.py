"""False-positive gate: documented-installer idioms must NOT auto-quarantine.

The deterministic scanner fires BP-DROPPER on any `curl … | sh` it can see — which
is correct (better to flag than miss), but means every benign repo's README/CI/
download page that shows its own install command would auto-quarantine without the
contextual attenuator layer. These tests pin the contract:

  * a benign repo full of documented installers (uv, docker, the project's own
    installer in README/CI/scripts/download-UI) scans to `review` or `clear`,
    NEVER `quarantine`, on the default (no-review, offline) path;
  * the genuinely-malicious evil-npm fixture STILL quarantines (the attenuators
    must not soften a real supply-chain / dropper attack) — the false-negative guard.

This is the highest-impact UX test in the suite: it is what makes `unmask run`
usable as a default instead of screaming QUARANTINE on every normal codebase.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
BENIGN_CI = FIXTURES / "benign-ci"
EVIL_NPM = FIXTURES / "evil-npm"


def _scan(target: Path, tmp_path: Path) -> dict:
    from unmask import MCDConfig, run_mcd
    result = run_mcd(str(target), MCDConfig(storage_root=str(tmp_path / ".mcd")))
    assert result.status == "completed", f"scan did not complete: {result.status}"
    return json.loads(Path(result.report_paths["json"]).read_text())


def test_benign_ci_does_not_quarantine(tmp_path):
    """A repo whose only fetch-and-execute is documented installer idioms in
    README / CI / install scripts / a download page must not auto-quarantine."""
    report = _scan(BENIGN_CI, tmp_path)
    rec = report["disposition"]["recommendation"]
    assert rec in ("review", "clear"), (
        f"benign-ci fixture scanned to {rec!r}, expected review/clear. "
        f"A documented-installer idiom is driving a false-positive quarantine. "
        f"Findings: {[(f.get('composition'), f.get('confidence'), f.get('title')) for f in report.get('findings', [])]}"
    )


def test_benign_ci_attenuators_recorded(tmp_path):
    """Every attenuated finding must carry the reason AND the false-negative risk
    note, so a reviewer can see exactly what was softened and what it could hide."""
    report = _scan(BENIGN_CI, tmp_path)
    attenuated = [f for f in report.get("findings", [])
                  if "originalConfidence" in f and f.get("confidence") < f["originalConfidence"]]
    assert attenuated, "expected at least one attenuated finding in benign-ci"
    for f in attenuated:
        assert f.get("attenuators"), f"finding {f.get('id')} attenuated but no reason recorded"
        assert f.get("attenuatorFalseNegativeRisk"), (
            f"finding {f.get('id')} attenuated but no false-negative-risk note recorded")


def test_benign_ci_findings_still_visible(tmp_path):
    """Attenuation reduces confidence, it never REMOVES a finding — a documented
    installer still surfaces as a review item so a human can catch a typosquat."""
    report = _scan(BENIGN_CI, tmp_path)
    # The README/CI curl|sh findings must still be present (just below quarantine bar).
    titles = [f.get("title", "") for f in report.get("findings", [])]
    assert any("execute" in t.lower() or "dropper" in t.lower() for t in titles), (
        "expected the documented-installer BP-DROPPER findings to remain visible (attenuated, not removed)")


def test_evil_npm_still_quarantines(tmp_path):
    """False-negative guard: the genuinely-malicious evil-npm fixture (a postinstall
    that beacons env to a collector and evals the response) must STILL quarantine —
    the contextual attenuators must not soften a real attack."""
    report = _scan(EVIL_NPM, tmp_path)
    assert report["disposition"]["recommendation"] == "quarantine", (
        "evil-npm did NOT quarantine — the attenuators softened a genuine attack. "
        "This is a false-negative regression.")
    assert report["summary"]["findingCount"] >= 1

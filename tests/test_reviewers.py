"""Agentic reviewer — loop, config resolution, and honest failure degradation.

Uses pydantic-ai's TestModel so the loop is exercised deterministically with no
live endpoint. A live smoke test is gated behind UNMASK_REVIEW_LIVE.
"""

from __future__ import annotations

import os

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.models.test import TestModel  # noqa: E402

from unmask.reviewers import (  # noqa: E402
    FindingReview, ReviewConfigError, ReviewModelConfig, build_reviewer, review_finding,
)

_FINDING = {
    "id": "mcd-1", "title": "Install-time payload path", "composition": "BP-SUPPLY",
    "severity": "high", "confidence": 0.7, "claim": "An install hook runs network code.",
    "disproofCriteria": ["The install code is a documented, reproducible build step."],
    "verification": [{"question": "What does the hook fetch?", "method": "static-source"}],
    "response": {"tier": 3},
}
_EVIDENCE = [
    {"atom": "PKGM.INSTALL", "location": {"path": "package.json", "line": 6},
     "evidence": {"matchedText": "node ./scripts/postinstall.js"}},
    {"atom": "NETW.HTTP", "location": {"path": "scripts/postinstall.js", "line": 4},
     "evidence": {"matchedText": "https.get"}},
]


def test_reviewer_loop_with_testmodel():
    review = review_finding(_FINDING, _EVIDENCE, agent=build_reviewer(model=TestModel()))
    assert isinstance(review, FindingReview)
    assert review.finding_id == "mcd-1"                  # pinned to the reviewed finding
    assert 0.0 <= review.reviewed_confidence <= 1.0
    assert 0 <= review.response_tier <= 5
    assert review.verdict in {
        "confirm", "escalate", "deescalate", "refute", "suppress", "needs_evidence", "needs_human",
    }


def test_config_resolves_openai_compatible(monkeypatch):
    monkeypatch.setenv("UNMASK_REVIEW_PROVIDER", "lmstudio")
    monkeypatch.setenv("UNMASK_REVIEW_MODEL", "local-model-27b")
    monkeypatch.delenv("UNMASK_REVIEW_BASE_URL", raising=False)
    c = ReviewModelConfig.from_env()
    assert c.model == "local-model-27b"
    assert c.base_url.endswith("/v1")


def test_config_missing_model_raises(monkeypatch):
    monkeypatch.setenv("UNMASK_REVIEW_PROVIDER", "custom")
    monkeypatch.delenv("UNMASK_REVIEW_MODEL", raising=False)
    with pytest.raises(ReviewConfigError):
        ReviewModelConfig.from_env()


def test_failure_degrades_to_needs_human():
    class _Boom:
        def run_sync(self, *a, **k):
            raise RuntimeError("endpoint unreachable")

    review = review_finding(_FINDING, _EVIDENCE, agent=_Boom())
    assert review.verdict == "needs_human"
    assert review.finding_id == "mcd-1"
    assert review.reviewed_confidence == 0.7  # keeps the engine's confidence, flagged


def test_review_assessment_adjudicates_and_persists(tmp_path):
    from pathlib import Path

    from unmask.ledger import LedgerStore
    from unmask.reviewers import review_assessment
    from unmask.scanner.assess import build_assessment
    from unmask.scanner.compose import compose_mcd
    from unmask.scanner.observe import observe

    fx = str(Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "evil-npm")
    obs, inv = observe(fx)
    assessment = build_assessment(compose_mcd(obs, inv), obs, inv, fx)

    reviews, overlay = review_assessment(assessment, agent=build_reviewer(model=TestModel()))
    assert len(reviews) == assessment["summary"]["findingCount"] == 4
    assert overlay["reviewedDisposition"]["recommendation"] in {"clear", "review", "quarantine"}
    assert overlay["engineDisposition"] == "quarantine"
    assert sum(overlay["counts"].values()) == 4

    led = LedgerStore(tmp_path / "run.db")
    led.create_run(run_id="r1", project_id="p", target_path=fx, target_root=fx,
                   storage_root=str(tmp_path), run_dir=str(tmp_path), config_json="{}")
    for r in reviews:
        led.record_judgment("r1", r, model="test")
    assert led.count_judgments("r1") == 4
    led.close()


@pytest.mark.skipif(os.environ.get("UNMASK_REVIEW_LIVE") != "1",
                    reason="live review; set UNMASK_REVIEW_LIVE=1 and UNMASK_REVIEW_* to run")
def test_live_review_smoke():
    review = review_finding(_FINDING, _EVIDENCE)
    assert isinstance(review, FindingReview)
    assert review.justification

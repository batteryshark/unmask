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


def test_mcd_run_review_attaches_adjudication(tmp_path):
    """`mcd run --review` (via run_mcd with an injected model) folds the reviewed
    disposition into the report and persists judgments to the ledger."""
    import json
    from pathlib import Path

    from unmask import MCDConfig, run_mcd
    from unmask.ledger import LedgerStore

    fx = str(Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "evil-npm")
    result = run_mcd(fx, MCDConfig(storage_root=str(tmp_path / ".mcd"), review=True),
                     review_model=TestModel())
    assert result.status == "completed"

    report = json.loads(Path(result.report_paths["json"]).read_text())
    assert "adjudication" in report
    assert report["adjudication"]["reviewedDisposition"]["recommendation"] in {"clear", "review", "quarantine"}
    assert report["adjudication"]["engineDisposition"] == "quarantine"

    led = LedgerStore(Path(result.run_dir) / "run.db")
    # One judgment per finding — every finding is reviewed, none dropped silently.
    # The count grows when the transform seam reveals hidden code (e.g. deobfuscation
    # of the postinstall payload), so pin the contract, not a hardcoded number.
    assert led.count_judgments(result.run_id) == result.finding_count
    assert led.count_judgments(result.run_id) >= 4
    led.close()

    assert "Reviewed:" in Path(result.report_paths["html"]).read_text()


def test_mcd_run_without_review_has_no_adjudication(tmp_path):
    import json
    from pathlib import Path

    from unmask import MCDConfig, run_mcd

    fx = str(Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "evil-npm")
    result = run_mcd(fx, MCDConfig(storage_root=str(tmp_path / ".mcd")))  # review off (default)
    report = json.loads(Path(result.report_paths["json"]).read_text())
    assert "adjudication" not in report


@pytest.mark.skipif(os.environ.get("UNMASK_REVIEW_LIVE") != "1",
                    reason="live review; set UNMASK_REVIEW_LIVE=1 and UNMASK_REVIEW_* to run")
def test_live_review_smoke():
    review = review_finding(_FINDING, _EVIDENCE)
    assert isinstance(review, FindingReview)
    assert review.justification


# --- batched record-tool review -------------------------------------------

def _assessment_with(n_findings: int):
    """A synthetic assessment with n findings + matching observations."""
    findings, observations = [], []
    for i in range(1, n_findings + 1):
        oid = f"obs-{i}"
        observations.append({"id": oid, "atom": "NETW.HTTP",
                             "location": {"path": f"f{i}.js", "line": i},
                             "evidence": {"matchedText": "https.get"}})
        findings.append({
            "id": f"mcd-{i}", "title": f"Finding {i}", "composition": "BP-DROPPER",
            "severity": "high", "confidence": 0.6, "claim": f"claim {i}",
            "evidence": [oid], "disproofCriteria": ["d"], "response": {"tier": 3},
        })
    return {
        "findings": findings, "observations": observations,
        "summary": {"findingCount": n_findings, "highestSeverity": "high"},
        "disposition": {"recommendation": "review"},
    }


class _StubBatchAgent:
    """A fake agent that calls record_finding_review for each finding in the prompt,
    simulating a well-behaved batch model. Records into the provided list."""

    def __init__(self, reviews_ref):
        self._reviews = reviews_ref
        self._turns = 0

    def run_sync(self, prompt):
        self._turns += 1
        import re
        from unmask.reviewers.schemas import FindingReview
        # Extract finding ids from the prompt and record a verdict for each.
        for fid in re.findall(r"## Finding (mcd-\d+)", prompt):
            i = int(fid.split("-")[1])
            self._reviews.append(FindingReview(
                finding_id=fid, verdict="deescalate",
                reviewed_confidence=0.4, response_tier=2,
                justification=f"stub review {i}",
            ))
        return None


class _SkippingAgent:
    """A misbehaving agent that records NOTHING — simulates a model that gives up.
    Every finding must fall through to needs_human."""

    def __init__(self, reviews_ref):
        self._reviews = reviews_ref

    def run_sync(self, prompt):
        return None


def test_batch_review_covers_all_findings_no_silent_drop():
    """A batch of 10 findings: the stub agent reviews all 10 → 10 verdicts."""
    from unmask.reviewers.batch import review_assessment_batched
    collected = []
    agent = _StubBatchAgent(collected)
    assessment = _assessment_with(10)
    reviews, overlay = review_assessment_batched(
        assessment, agent=agent, reviews=collected, batch_size=5)
    assert len(reviews) == 10
    assert {r.finding_id for r in reviews} == {f"mcd-{i}" for i in range(1, 11)}
    # None dropped to needs_human (the stub reviewed them all).
    assert all(r.verdict == "deescalate" for r in reviews)
    assert agent._turns == 2  # 10 findings / batch_size 5 = 2 turns


def test_batch_review_skipped_findings_become_needs_human():
    """If the model skips findings (gives up / output limit), they become
    needs_human — never a silent drop or clear."""
    from unmask.reviewers.batch import review_assessment_batched
    collected = []
    agent = _SkippingAgent(collected)
    assessment = _assessment_with(8)
    reviews, overlay = review_assessment_batched(
        assessment, agent=agent, reviews=collected, batch_size=4)
    assert len(reviews) == 8
    assert all(r.verdict == "needs_human" for r in reviews)
    assert all(r.finding_id for r in reviews)  # each pinned to a real finding


def test_batch_review_turn_bound_is_enforced():
    """The max_turns cap stops a runaway model; unreviewed findings → needs_human."""
    from unmask.reviewers.batch import review_assessment_batched
    collected = []
    agent = _StubBatchAgent(collected)
    assessment = _assessment_with(20)
    reviews, overlay = review_assessment_batched(
        assessment, agent=agent, reviews=collected, batch_size=5, max_turns=1)
    # Only 1 turn = at most 5 findings reviewed (one batch); the rest → needs_human.
    reviewed = {r.finding_id for r in reviews if r.verdict != "needs_human"}
    fell_through = {r.finding_id for r in reviews if r.verdict == "needs_human"}
    assert len(reviewed) <= 5
    assert len(reviewed) + len(fell_through) == 20


def test_small_assessment_uses_single_finding_path():
    """≤ SINGLE_REVIEW_THRESHOLD findings: the batch path delegates to the cheaper
    single-finding reviewer (no batch tool loop spun up)."""
    from unmask.reviewers import review_assessment_batched, SINGLE_REVIEW_THRESHOLD
    assessment = _assessment_with(SINGLE_REVIEW_THRESHOLD)
    # TestModel drives the single-finding agent; no batch agent needed.
    reviews, overlay = review_assessment_batched(assessment, model=TestModel())
    assert len(reviews) == SINGLE_REVIEW_THRESHOLD
    assert all(r.finding_id for r in reviews)

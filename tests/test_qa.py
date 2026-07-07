"""Rule-tuning QA — deterministic clustering, suggestion loop, and integration."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.models.test import TestModel  # noqa: E402

from unmask.qa import cluster_noise, suggest_rule_tunings  # noqa: E402
from unmask.qa.agent import build_qa_agent  # noqa: E402
from unmask.reviewers import FindingReview  # noqa: E402


def _assessment():
    # Three BP-OBFEXEC findings from the same rule + one confirmed BP-SUPPLY.
    obs = [{"id": f"obs-{i}", "atom": "XFRM.ENCODE", "rule_id": "sig.xfrm.encode.base64",
            "location": {"path": f"f{i}.js", "line": 1}} for i in range(3)]
    findings = [{"id": f"mcd-{i}", "composition": "BP-OBFEXEC", "severity": "high",
                 "confidence": 0.6, "title": "obf", "claim": "decode+exec",
                 "evidence": [f"obs-{i}"]} for i in range(3)]
    findings.append({"id": "mcd-9", "composition": "BP-SUPPLY", "severity": "high",
                     "confidence": 0.7, "title": "supply", "evidence": []})
    return {"findings": findings, "observations": obs}


def _judgments():
    js = [FindingReview(finding_id=f"mcd-{i}", verdict="suppress", reviewed_confidence=0.1,
                        response_tier=0, excluded_from_disposition=True, justification="rule noise")
          for i in range(3)]
    js.append(FindingReview(finding_id="mcd-9", verdict="confirm", reviewed_confidence=0.7,
                            response_tier=3, justification="real"))
    return js


def test_cluster_groups_suppressed_ignores_confirmed():
    clusters = cluster_noise(_assessment(), _judgments())
    assert len(clusters) == 1                       # only the suppressed BP-OBFEXEC cluster
    assert clusters[0]["size"] == 3
    assert clusters[0]["composition"] == "BP-OBFEXEC"
    assert "sig.xfrm.encode.base64" in clusters[0]["rule_ids"]
    assert "mcd-9" not in clusters[0]["finding_ids"]  # the confirmed finding is not noise


def test_suggest_rule_tunings_with_testmodel():
    sugg = suggest_rule_tunings(_assessment(), _judgments(), agent=build_qa_agent(model=TestModel()))
    assert sugg
    for x in sugg:
        assert x.finding_ids and x.risk           # every suggestion cites findings + names FN risk


def test_singleton_suppression_yields_no_cluster_suggestion():
    a = _assessment()
    a["findings"], a["observations"] = a["findings"][:1], a["observations"][:1]
    j = [FindingReview(finding_id="mcd-0", verdict="suppress", reviewed_confidence=0.1,
                       response_tier=0, excluded_from_disposition=True, justification="one-off")]
    assert suggest_rule_tunings(a, j, agent=build_qa_agent(model=TestModel())) == []


def test_qa_degrades_to_human_review():
    class _Boom:
        def run_sync(self, *a, **k):
            raise RuntimeError("qa endpoint down")

    sugg = suggest_rule_tunings(_assessment(), _judgments(), agent=_Boom())
    assert len(sugg) == 1 and sugg[0].kind == "needs-human-rule-review"
    assert sugg[0].risk  # required


def test_mcd_run_post_report_qa_writes_artifact(tmp_path):
    import json

    from unmask import MCDConfig, run_mcd

    fx = str(Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "evil-npm")
    result = run_mcd(fx, MCDConfig(storage_root=str(tmp_path / ".mcd"),
                                   review=True, post_report_qa="rules"),
                     review_model=TestModel())
    qa = Path(result.run_dir) / "reports" / "qa.json"
    assert qa.is_file()
    data = json.loads(qa.read_text())
    assert data["kind"] == "rule-tuning-qa"
    assert "suggestions" in data and "not part of the target" in data["note"].lower()

"""Assess gate: native assessment reproduces the oracle's disposition + summary.

The clean-rebuilt assessment prose/structure may differ from the old renderer, but
the *semantic contract* — disposition and the severity/confidence/composition
summary — must match the frozen reference on the corpus.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from unmask.scanner.assess import build_assessment
from unmask.scanner.compose import compose_mcd
from unmask.scanner.observe import observe

REPO_ROOT = Path(__file__).resolve().parents[1]

_CORPUS = [
    ("evil-npm", "tests/fixtures/evil-npm"),
    ("benign-pkg", "tests/oracle/fixtures/benign-pkg"),
    ("py-curlpipe", "tests/oracle/fixtures/py-curlpipe"),
    ("obf-js", "tests/oracle/fixtures/obf-js"),
]


def _oracle(name):
    return json.loads((REPO_ROOT / "tests" / "oracle" / "golden" / name / "assessment.json").read_text())


def _summary_keys(s):
    return {k: s.get(k) for k in
            ("findingCount", "highestSeverity", "highestConfidence", "compositions")}


@pytest.mark.parametrize("name,rel", _CORPUS, ids=[c[0] for c in _CORPUS])
def test_assessment_matches_oracle(name, rel):
    obs, inv = observe(str(REPO_ROOT / rel))
    findings = compose_mcd(obs, inv)
    native = build_assessment(findings, obs, inv, str(REPO_ROOT / rel))
    gold = _oracle(name)

    assert native["disposition"]["recommendation"] == gold["disposition"]["recommendation"]
    assert _summary_keys(native["summary"]) == _summary_keys(gold["summary"])


def test_evil_npm_quarantine_and_correlation():
    rel = "tests/fixtures/evil-npm"
    obs, inv = observe(str(REPO_ROOT / rel))
    a = build_assessment(compose_mcd(obs, inv), obs, inv, str(REPO_ROOT / rel))
    assert a["disposition"]["recommendation"] == "quarantine"
    # The four findings all cite scripts/postinstall.js → one cross-signal cluster.
    assert len(a["correlations"]) == 1
    assert a["correlations"][0]["crossSignal"] is True

"""Assess gate: native assessment reproduces the oracle's disposition + summary.

The clean-rebuilt assessment prose/structure may differ from the old renderer, but
the *semantic contract* — disposition and the severity/confidence/composition
summary — must match the frozen reference on the corpus.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from unmask.scanner.assess import build_assessment
from unmask.scanner.assess.render import render_html
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


# --- html render contract --------------------------------------------------

# Any external resource loaded by a stylesheet, script, or @import would break
# "self-contained" (and could exfiltrate on open). Match the three vectors.
_EXTERNAL_RESOURCE_RE = re.compile(
    r"""(?:
          <link\b[^>]*\bhref\s*=\s*["']?\s*https?://   # <link href="http...">
        | <script\b[^>]*\bsrc\s*=\s*["']?\s*https?://   # <script src="http...">
        | @import\b[^;]*https?://                       # @import url(http...)
        )""",
    re.IGNORECASE | re.VERBOSE,
)


@pytest.mark.parametrize("name,rel", _CORPUS, ids=[c[0] for c in _CORPUS])
def test_render_html_self_contained(name, rel):
    obs, inv = observe(str(REPO_ROOT / rel))
    a = build_assessment(compose_mcd(obs, inv), obs, inv, str(REPO_ROOT / rel))
    html = render_html(a)

    # Self-contained, well-formed document.
    assert html.lower().startswith("<!doctype html>")
    assert "</html>" in html
    # No external stylesheet / script / @import references (self-contained + safe).
    assert not _EXTERNAL_RESOURCE_RE.search(html), \
        f"{name}: html references an external resource"

    # Faithfully presents the disposition and every finding.
    rec = a["disposition"]["recommendation"]
    assert rec.upper() in html
    for f in a["findings"]:
        assert f["title"] in html

    # The two-axis principle is visible in the markup, and the contract note
    # is carried through as the footer disclaimer.
    assert "severity" in html.lower() and "confidence" in html.lower()
    assert "not a maliciousness verdict" in html.lower()


def test_render_html_escapes_attacker_evidence():
    """Attacker-controlled evidence text must be HTML-escaped, not injected raw."""
    payload = "<script>alert('xss')</script>"
    assessment = {
        "disposition": {"recommendation": "review", "rationale": payload, "drivers": [payload]},
        "summary": {"findingCount": 1, "highestSeverity": "high",
                    "highestConfidence": 0.6, "highestConfidenceLabel": "medium",
                    "compositions": []},
        "executiveSummary": {"text": payload},
        "findings": [{
            "title": payload, "composition": payload, "severity": "high",
            "confidence": 0.6, "confidenceLabel": "medium", "claim": payload,
            "disproofCriteria": [payload],
            "verification": [{"question": payload, "method": payload, "reason": payload}],
            "response": {"tier": 3, "summary": payload, "actions": [payload]},
            "evidence": ["obs-x"],
        }],
        "correlations": [{"narrative": payload, "insights": [payload]}],
        "coverage": {"notes": [payload]},
        "observations": [{
            "id": "obs-x", "atom": payload, "method": "static-source",
            "location": {"path": payload, "line": 1},
            "evidence": {"summary": payload, "matchedText": payload},
        }],
        "contract": {"note": payload},
        "target": {"path": payload},
    }
    html = render_html(assessment)
    # The raw payload must never appear; only its escaped form.
    assert "<script>alert(" not in html
    assert "&lt;script&gt;alert(" in html

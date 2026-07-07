"""Compose gate: native compose over native observe reproduces the oracle findings.

The BP-* compositions, their severity, and their confidence must match the frozen
reference on the corpus — the parity bar for the interpretive layer.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from unmask.scanner.compose import compose_mcd
from unmask.scanner.observe import observe

REPO_ROOT = Path(__file__).resolve().parents[1]

_CORPUS = [
    ("evil-npm", "tests/fixtures/evil-npm"),
    ("benign-pkg", "tests/oracle/fixtures/benign-pkg"),
    ("py-curlpipe", "tests/oracle/fixtures/py-curlpipe"),
    ("obf-js", "tests/oracle/fixtures/obf-js"),
]


def _golden_findings(name: str):
    path = REPO_ROOT / "tests" / "oracle" / "golden" / name / "findings.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _shape(findings):
    return sorted((f.get("composition"), f.get("severity"), f.get("confidence")) for f in findings)


@pytest.mark.parametrize("name,rel", _CORPUS, ids=[c[0] for c in _CORPUS])
def test_compose_matches_oracle(name, rel):
    obs, inv = observe(str(REPO_ROOT / rel))
    native = _shape(compose_mcd(obs, inv))
    golden = _shape(_golden_findings(name))
    assert native == golden, f"{name}: compose diverges from oracle\n native={native}\n oracle={golden}"


def test_evil_npm_full_composition_set():
    obs, inv = observe(str(REPO_ROOT / "tests" / "fixtures" / "evil-npm"))
    comps = {f.get("composition") for f in compose_mcd(obs, inv)}
    assert comps == {"BP-SUPPLY", "BP-OBFEXEC", "BP-BACKDOOR", "BP-TROJAN"}

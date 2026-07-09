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


def _obs(atom, path, oid, line=1):
    from unmask.scanner.observe.atoms import Observation
    return Observation(atom=atom, confidence=0.7, method="content-regex",
                       path=path, line=line, id=oid)


def test_obfuscation_finding_is_high_and_dedups_by_top_level_artifact():
    # two carved members of ONE binary, both string-concealed → ONE high obfuscation finding
    obs = [_obs("XFRM.STRCON", "bin!carved-000.js", "o1"),
           _obs("XFRM.STRCON", "bin!carved-001.js", "o2")]
    obf = [f for f in compose_mcd(obs, None) if f.get("composition") == "BP-OBFUSCATION"]
    assert len(obf) == 1 and obf[0]["severity"] == "high"


def test_plain_minification_is_not_obfuscation():
    # short names (RENAME) + a lone base64 (ENCODE) are normal shipped JS, not concealment
    obs = [_obs("XFRM.RENAME", "app.min.js", "o1"), _obs("XFRM.ENCODE", "app.min.js", "o2")]
    assert not any(f.get("composition") == "BP-OBFUSCATION" for f in compose_mcd(obs, None))

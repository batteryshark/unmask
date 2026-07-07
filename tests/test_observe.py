"""Observe slice: data-driven inventory + content-atom extraction."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from unmask.scanner.observe import (
    build_inventory, extract_calls, extraction_mode, observe, observe_callee, observe_content,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
EVIL = REPO_ROOT / "tests" / "fixtures" / "evil-npm"
BENIGN = REPO_ROOT / "tests" / "oracle" / "fixtures" / "benign-pkg"
CURLPIPE = REPO_ROOT / "tests" / "oracle" / "fixtures" / "py-curlpipe"


def _by_rel(inv):
    return {f.rel: f for f in inv.files}


def test_inventory_classifies_corpus():
    inv = _by_rel(build_inventory(str(EVIL)))
    assert inv["package.json"].kind == "manifest"
    assert inv["index.js"].kind == "source" and inv["index.js"].language == "javascript"
    assert inv["scripts/postinstall.js"].language == "javascript"


def test_inventory_skips_dirs_and_detects_binary(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("x = 1\n")
    (tmp_path / "node_modules" / "dep").mkdir(parents=True)
    (tmp_path / "node_modules" / "dep" / "index.js").write_text("//dep\n")
    (tmp_path / "lib.so").write_bytes(b"\x7fELF\x02\x01\x01\x00binary")

    rels = {f.rel: f for f in build_inventory(str(tmp_path)).files}
    assert "src/a.py" in rels and rels["src/a.py"].language == "python"
    assert rels["lib.so"].kind == "binary"
    assert not any(r.startswith("node_modules") for r in rels), "node_modules must be pruned"


def test_content_observe_finds_urls():
    inv = build_inventory(str(CURLPIPE))
    obs = observe_content(inv)
    url_hits = [o for o in obs if o.evidence and "http" in o.evidence]
    assert url_hits, f"expected a URL content atom; got {[(o.atom, o.evidence) for o in obs]}"
    # Every content observation is tagged as string evidence with a source line.
    assert all(o.method == "content-regex" for o in obs)
    assert all(o.line and o.line >= 1 for o in url_hits)


def test_benign_has_no_url_atoms():
    inv = build_inventory(str(BENIGN))
    obs = observe_content(inv)
    assert not [o for o in obs if o.evidence and "http" in o.evidence]


def test_callee_extraction_and_classification():
    obs = {(o.atom, o.evidence) for o in observe_callee(build_inventory(str(EVIL)))}
    assert ("NETW.HTTP", "https.get") in obs
    assert ("LOAD.EVAL", "eval") in obs
    py = {o.atom for o in observe_callee(build_inventory(str(CURLPIPE)))}
    assert {"EXEC.SHELL", "NETW.HTTP"} <= py  # os.system + urlopen


def test_ast_ignores_calls_inside_string_literals(tmp_path):
    # AST's headline advantage over regex: a call-looking token inside a string
    # literal is not a call.
    (tmp_path / "m.py").write_text(
        'note = "run os.system(rm) if evil"\nimport os\nos.getcwd()\n', encoding="utf-8"
    )
    callees = {c for c, _ in extract_calls((tmp_path / "m.py").read_text(), "python")}
    assert "os.getcwd" in callees
    if extraction_mode() == "tree-sitter":
        assert "os.system" not in callees, "AST must not match a call inside a string"


_CORPUS = [
    ("evil-npm", "tests/fixtures/evil-npm"),
    ("benign-pkg", "tests/oracle/fixtures/benign-pkg"),
    ("py-curlpipe", "tests/oracle/fixtures/py-curlpipe"),
    ("obf-js", "tests/oracle/fixtures/obf-js"),
]


@pytest.mark.parametrize("name,rel", _CORPUS, ids=[c[0] for c in _CORPUS])
def test_native_observe_no_under_detection(name, rel):
    """The assembled native observe() must catch every atom the oracle did."""
    obs, _ = observe(str(REPO_ROOT / rel))
    native = {o.atom for o in obs}
    golden = {o["atom"] for o in
              json.loads((REPO_ROOT / "tests" / "oracle" / "golden" / name / "observations.json").read_text())}
    missing = golden - native
    assert not missing, f"{name}: native observe under-detects vs oracle: {sorted(missing)}"

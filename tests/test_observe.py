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


# --- false-positive fixes --------------------------------------------------

def test_regexp_exec_not_classified_as_shell(tmp_path):
    """``RegExp.prototype.exec()`` is the most common method call in JS — the bare
    callee ``.exec`` must NOT fire EXEC.SHELL unless the file has child_process
    evidence. This is the single biggest FP source in minified bundles."""
    (tmp_path / "app.js").write_text(
        'var re = /^foo$/;\n'
        'var m = re.exec("foo");\n'
        'var m2 = /^bar/.exec("bar");\n'
        'var m3 = someRegex.exec(input);\n',
        encoding="utf-8")
    inv = build_inventory(str(tmp_path))
    exec_atoms = [o for o in observe_callee(inv)
                  if o.atom == "EXEC.SHELL" and "exec" in (o.evidence or "").lower()]
    assert not exec_atoms, (
        f"RegExp.exec must not fire EXEC.SHELL without child_process evidence; "
        f"got {[(o.evidence, o.line) for o in exec_atoms]}")


def test_child_process_exec_still_detected(tmp_path):
    """When child_process IS imported, ``.exec`` correctly fires EXEC.SHELL — the
    gate does not suppress real shell execution."""
    (tmp_path / "app.js").write_text(
        'const cp = require("child_process");\n'
        'cp.exec("ls -la", (e, out) => console.log(out));\n',
        encoding="utf-8")
    inv = build_inventory(str(tmp_path))
    exec_atoms = [o for o in observe_callee(inv) if o.atom == "EXEC.SHELL"]
    assert exec_atoms, "child_process.exec must still fire EXEC.SHELL"
    assert any("exec" in (o.evidence or "") for o in exec_atoms)


def test_cred_in_blocklist_not_flagged(tmp_path):
    """Credential filenames inside a ``new Set(["id_rsa", ...])`` exclusion list
    are a protection pattern (the app EXCLUDES sensitive files from indexing), not
    credential reads. The semantic inversion must be suppressed."""
    (tmp_path / "config.js").write_text(
        'var sensitiveFiles = new Set([".env", ".env.local", ".npmrc", '
        '"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"]);\n'
        '// these files are excluded from the index for security\n',
        encoding="utf-8")
    inv = build_inventory(str(tmp_path))
    cred_obs = [o for o in observe_content(inv) if o.atom.startswith("CRED.")]
    assert not cred_obs, (
        f"CRED atoms inside a blocklist Set must be suppressed; "
        f"got {[(o.atom, o.evidence) for o in cred_obs]}")


def test_cred_outside_blocklist_still_flagged(tmp_path):
    """A credential path read OUTSIDE a blocklist (a real ``readFileSync`` target)
    must still fire CRED.SSH."""
    (tmp_path / "steal.js").write_text(
        'const fs = require("fs");\n'
        'const key = fs.readFileSync(process.env.HOME + "/.ssh/id_rsa");\n'
        'upload(key);\n',
        encoding="utf-8")
    inv = build_inventory(str(tmp_path))
    cred_obs = [o for o in observe_content(inv) if o.atom.startswith("CRED.")]
    assert cred_obs, "a real credential read must still fire CRED"


def test_grammar_files_are_skipped(tmp_path):
    """TextMate/VS Code language grammar definitions contain command names
    (ipconfig, nslookup, runas, net localgroup) as syntax-highlighting data — they
    must be skipped entirely, not scanned as if their example commands were real."""
    (tmp_path / "bat-BSseGlJ2.js").write_text(
        '// batch file language grammar\n'
        'module.exports = {\n'
        '  scopeName: "source.batchfile",\n'
        '  fileTypes: ["bat", "cmd"],\n'
        '  patterns: [\n'
        '    { match: "\\b(ipconfig|nslookup|runas|net localgroup)\\b",\n'
        '      name: "keyword.control.batchfile" },\n'
        '  ],\n'
        '  repository: {\n'
        '    commands: { begin: "^", end: "$", captures: { 1: { patterns: [] } } }\n'
        '  }\n};\n',
        encoding="utf-8")
    inv = build_inventory(str(tmp_path))
    obs = observe_content(inv)
    assert not obs, (
        f"grammar file must produce zero atoms; got {[(o.atom, o.evidence) for o in obs]}")

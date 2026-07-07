"""Native signature matcher — unit tests + callee parity vs a frozen reference map.

The parity map (`fixtures/callee_parity_map.json`) was frozen from the old engine's
`SignaturePack.classify_callee` over a large candidate corpus, just before the
transitional `_vendor/` engine was deleted. The native classifier must reproduce it
byte-for-byte; any drift is a matcher bug. Regenerate only from a trusted reference.
"""

from __future__ import annotations

import json
from pathlib import Path

from unmask.scanner.signatures import Signatures, vendored_packs_dir

PACKS = vendored_packs_dir()
_PARITY_MAP = Path(__file__).parent / "fixtures" / "callee_parity_map.json"


def _sigs() -> Signatures:
    return Signatures.load_vendored(PACKS)


# --- structural -----------------------------------------------------------

def test_packs_load():
    s = _sigs()
    # 90 upstream + 2 added (load.eval.python.dynamic-exec, xfrm.encode.base64).
    assert len(s.callee_rules) == 92
    # 106 upstream + 1 added (remote-download-cmd -> NETW.HTTP for curl|sh droppers).
    assert len(s.packs["content"].content_rules) == 107
    assert len(s.packs["binary-import"].match_rules) == 11


def test_known_callee_classifications():
    s = _sigs()
    assert s.classify_callee("popen", "python").atom == "EXEC.SHELL"            # base mode
    assert s.classify_callee("subprocess.popen", "python").atom == "EXEC.SHELL"  # dotted -> base
    assert s.classify_callee("os::system", "cpp").atom == "EXEC.SHELL"          # :: normalized
    assert s.classify_callee("exec", "python").atom == "LOAD.EVAL"              # python exec = code exec
    assert s.classify_callee("definitely_not_a_known_callee", "python") is None


def test_content_and_import_matchers():
    s = _sigs()
    hits = s.classify_content("connect ftp://user@host/x then done", "*")
    assert any(h.atom == "NETW.FTP" for h in hits)
    imp = s.classify_import("VirtualAllocEx")
    assert imp is not None and imp.atom == "EXEC.INJECT"


# --- parity: native matcher locked to the frozen reference map ------------

def test_callee_parity_vs_frozen_map():
    entries = json.loads(_PARITY_MAP.read_text(encoding="utf-8"))
    native = _sigs()
    mismatches = []
    for e in entries:
        got = native.classify_callee(e["candidate"], e["lang"])
        got_t = list(got.as_tuple()) if got else None
        if got_t != e["expected"]:
            mismatches.append((e["candidate"], e["lang"], got_t, e["expected"]))
    assert not mismatches, (
        f"{len(mismatches)}/{len(entries)} callee mismatches vs frozen reference map; "
        f"first 5: {mismatches[:5]}"
    )
    assert len(entries) > 2000
    assert any(e["expected"] for e in entries)  # the corpus has real positives

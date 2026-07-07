"""Native signature matcher — unit tests + callee parity vs the reference engine.

The parity test locks the native callee classifier to the old engine's
`SignaturePack.classify_callee` over a large candidate corpus derived from the
pack values (the same idea as the TS scan-core 291/291 harness). Both sides read
the SAME vendored `source-callees.json`, so any divergence is a matcher bug.

The reference is imported from the transitional `_vendor/` engine; once that is
deleted at the end of the compose slice, freeze the expected map instead.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from unmask.scanner.signatures import Signatures, load_pack, vendored_packs_dir

PACKS = vendored_packs_dir()
_UNMASK_PKG = Path(__file__).resolve().parents[1] / "packages" / "unmask" / "src" / "unmask"
_VENDOR = _UNMASK_PKG / "_vendor"


def _sigs() -> Signatures:
    return Signatures.load_vendored(PACKS)


# --- structural -----------------------------------------------------------

def test_packs_load():
    s = _sigs()
    assert len(s.callee_rules) == 90
    assert len(s.packs["content"].content_rules) == 106
    assert len(s.packs["binary-import"].match_rules) == 11


def test_known_callee_classifications():
    s = _sigs()
    assert s.classify_callee("popen", "python").atom == "EXEC.SHELL"          # base mode
    assert s.classify_callee("subprocess.popen", "python").atom == "EXEC.SHELL"  # dotted -> base
    assert s.classify_callee("os::system", "cpp").atom == "EXEC.SHELL"         # :: normalized
    assert s.classify_callee("definitely_not_a_known_callee", "python") is None


def test_content_and_import_matchers():
    s = _sigs()
    hits = s.classify_content("connect ftp://user@host/x then done", "*")
    assert any(h.atom == "NETW.FTP" for h in hits)
    imp = s.classify_import("VirtualAllocEx")
    assert imp is not None and imp.atom == "EXEC.INJECT"


# --- parity vs reference engine ------------------------------------------

def _reference_pack():
    if str(_VENDOR) not in sys.path:
        sys.path.insert(0, str(_VENDOR))
    from engine.signatures import load_signature_pack  # type: ignore
    return load_signature_pack(PACKS / "source-callees.json")


def _reference_available() -> bool:
    try:
        _reference_pack()
        return True
    except Exception:
        return False


def _candidate_corpus(native: Signatures):
    """(candidate, lang) pairs exercising every mode across languages + negatives."""
    langs = {"python", "javascript", "c", "cpp", "ruby", "go", "rust", "shell", "nope"}
    seen: set[tuple[str, str]] = set()
    for rule in native.callee_rules:
        langs |= set(rule.languages[:2])
        for v in rule.values:
            for cand in (v, f"pkg.{v}", f"a.b.{v}", f"{v}x", f"x{v}", v.upper(), f"os::{v}"):
                for lang in (rule.languages[0], "python", "nope"):
                    seen.add((cand, lang))
    for neg in ("", "totally_unrelated", "foo.bar.baz", "x.y"):
        for lang in langs:
            seen.add((neg, lang))
    return sorted(seen)


@pytest.mark.skipif(not _reference_available(), reason="reference _vendor engine unavailable")
def test_callee_parity_vs_reference():
    native = _sigs()
    ref = _reference_pack()
    corpus = _candidate_corpus(native)

    mismatches = []
    for cand, lang in corpus:
        got = native.classify_callee(cand, lang)
        want = ref.classify_callee(cand, lang)
        got_t = got.as_tuple() if got else None
        if got_t != want:
            mismatches.append((cand, lang, got_t, want))

    assert not mismatches, (
        f"{len(mismatches)}/{len(corpus)} callee mismatches vs reference; "
        f"first 5: {mismatches[:5]}"
    )
    # Guard the harness actually exercised a real corpus with real positives.
    assert len(corpus) > 2000
    assert any(native.classify_callee(c, l) for c, l in corpus)

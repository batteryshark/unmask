"""Positive (and negative-control) proof that native dataflow/reachability fire.

The oracle gate proves the dataflow pass does not OVER-detect on the frozen corpus
(BP-OBFEXEC stays 0.6, etc.). These tests prove the complementary half: on a
crafted single-file target where a value is genuinely tainted source-to-sink, the
pass PROVES the path and the compose layer raises confidence to the proven value.
Capability is real, not a no-op — and the negative control shows it does not fire
when the link is only co-occurrence.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from unmask.scanner.compose import compose_mcd
from unmask.scanner.observe import observe, prove_paths
from unmask.scanner.observe.callgraph import analyze as analyze_reachability
from unmask.scanner.observe.dataflow import analyze_inventory as analyze_dataflow

REPO_ROOT = Path(__file__).resolve().parents[1]
FIX = REPO_ROOT / "tests" / "fixtures" / "proven-dataflow"

ts_only = pytest.mark.skipif(
    __import__("unmask.scanner.observe.callee", fromlist=["ts_available"]).ts_available() is False,
    reason="dataflow taint requires the tree-sitter grammar (regex fallback is capability-free)",
)


def _obfexec(findings):
    return next((f for f in findings if f.get("composition") == "BP-OBFEXEC"), None)


def _dropper(findings):
    return next((f for f in findings if f.get("composition") == "BP-DROPPER"), None)


@ts_only
def test_prove_decode_exec_python():
    """b64decode -> exec through a single-assignment variable is a proven path."""
    src = (FIX / "decode_exec.py").read_text()
    paths = prove_paths(src, "python")
    kinds = {p["kind"] for p in paths}
    assert "decode-exec" in kinds, paths
    hit = next(p for p in paths if p["kind"] == "decode-exec")
    assert hit["sourceKind"] == "decode" and hit["sinkKind"] == "exec"
    assert hit["variable"] == "code"


@ts_only
def test_prove_fetch_exec_dropper_js():
    """A fetch result flowing into eval() is a proven dropper (fetch -> exec)."""
    src = (FIX / "fetch_exec.js").read_text()
    paths = prove_paths(src, "javascript")
    hit = next((p for p in paths if p["kind"] == "dropper"), None)
    assert hit is not None, paths
    assert hit["sourceKind"] == "fetch" and hit["sinkKind"] == "exec"


@ts_only
def test_unproven_decode_stays_cooccurrence():
    """A user-defined decode helper is NOT a recognized source: no proof (guards
    against over-detection that would drift the oracle)."""
    src = (FIX / "unproven_decode.js").read_text()
    assert prove_paths(src, "javascript") == []


@ts_only
def test_dataflow_upgrades_obfexec_confidence():
    """End-to-end: the proven decode-exec path raises BP-OBFEXEC 0.6 -> 0.85."""
    target = str(FIX / "decode_exec.py")
    obs, inv = observe(target)
    assert inv.dataflow.get("decode_exec.py"), "pipeline must populate inv.dataflow"

    finding = _obfexec(compose_mcd(obs, inv))
    assert finding is not None, "decode + eval must compose BP-OBFEXEC"
    assert finding["confidence"] == 0.85, "proven decode-exec must reach the proven confidence"
    assert "PROVEN" in finding["claim"]


def test_unproven_fixture_obfexec_is_cooccurrence():
    """The negative-control fixture composes BP-OBFEXEC at co-occurrence (0.6),
    NOT the proven value — the same confidence the obf-js oracle records. Runs in
    both AST and regex mode: without a proof, confidence must not be raised."""
    target = str(FIX / "unproven_decode.js")
    obs, inv = observe(target)
    finding = _obfexec(compose_mcd(obs, inv))
    assert finding is not None
    assert finding["confidence"] == 0.6, "unproven decode must stay at co-occurrence"


@ts_only
def test_reachability_reports_reachable_sink():
    """Cross-function reachability: an egress sink inside a function reached from
    module top-level is reported (entry -> function chain)."""
    target = str(REPO_ROOT / "tests" / "oracle" / "fixtures" / "py-curlpipe")
    _, inv = observe(target)
    sinks = (inv.reachability or {}).get("reachableSinks") or []
    assert any(s["file"] == "loader.py" and "egress" in s["sinkKinds"] for s in sinks), inv.reachability
    # sanity: the standalone analyzers agree with what the pipeline stored.
    assert analyze_dataflow(inv) == inv.dataflow
    assert analyze_reachability(inv) == inv.reachability

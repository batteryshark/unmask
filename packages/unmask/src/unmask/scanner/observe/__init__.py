"""Observe — walk a target and emit judgment-free atoms (slice 2 of the rebuild).

Pipeline (mirrors the reference `engine.observe`, rebuilt clean and data-driven):

    inventory     walk + classify files       (reference/file-classification.json)
    content       regex content atoms         (content-surfaces pack, slice-1 matcher)
    callee        call-site atoms             (source-callees pack)
    manifest      PKGM.INSTALL + relationships
    supply        supply-chain / lifecycle atoms
    dataflow      intra-file taint (source -> sink proven paths)
    reachability  cross-file call-graph reachable sinks

Atoms say what code *can do*; interpretation (BP-* compositions) is the compose
slice. Dataflow/reachability upgrade same-file co-occurrence to a proven path,
which the compose layer reads to raise confidence — and only then.
"""

from __future__ import annotations

from unmask.scanner.observe.atoms import Observation
from unmask.scanner.observe.callee import extract_calls, extraction_mode, observe_callee
from unmask.scanner.observe.callgraph import analyze as analyze_reachability
from unmask.scanner.observe.content import observe_content
from unmask.scanner.observe.dataflow import analyze_inventory as analyze_dataflow
from unmask.scanner.observe.dataflow import prove_paths
from unmask.scanner.observe.inventory import FileEntry, Inventory, build_inventory
from unmask.scanner.observe.manifest import observe_manifest
from unmask.scanner.observe.pipeline import observe
from unmask.scanner.observe.supply import observe_supply

__all__ = [
    "observe", "Observation", "FileEntry", "Inventory", "build_inventory",
    "observe_content", "observe_callee", "observe_manifest", "observe_supply",
    "extract_calls", "extraction_mode",
    "analyze_dataflow", "prove_paths", "analyze_reachability",
]

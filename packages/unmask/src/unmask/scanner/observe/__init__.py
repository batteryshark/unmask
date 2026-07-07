"""Observe — walk a target and emit judgment-free atoms (slice 2 of the rebuild).

Pipeline (mirrors the reference `engine.observe`, rebuilt clean and data-driven):

    inventory  walk + classify files          (reference/file-classification.json)
    content    regex content atoms            (content-surfaces pack, slice-1 matcher)
    callee     call-site atoms                (source-callees pack)  [next sub-slice]
    manifest   PKGM.INSTALL + relationships    [next sub-slice]

Atoms say what code *can do*; interpretation (BP-* compositions) is the compose
slice. The reference oracle was captured in regex-fallback mode, so parity needs
no tree-sitter — callee extraction reproduces the regex path (tree-sitter is a
later fidelity upgrade).
"""

from __future__ import annotations

from unmask.scanner.observe.atoms import Observation
from unmask.scanner.observe.callee import extract_calls, extraction_mode, observe_callee
from unmask.scanner.observe.content import observe_content
from unmask.scanner.observe.inventory import FileEntry, Inventory, build_inventory
from unmask.scanner.observe.manifest import observe_manifest
from unmask.scanner.observe.pipeline import observe
from unmask.scanner.observe.supply import observe_supply

__all__ = [
    "observe", "Observation", "FileEntry", "Inventory", "build_inventory",
    "observe_content", "observe_callee", "observe_manifest", "observe_supply",
    "extract_calls", "extraction_mode",
]

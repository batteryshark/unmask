"""Assemble the observe passes into `observe(target) -> (observations, inventory)`.

    inventory  ->  content + callee + manifest + supply  ->  dedup  ->  atoms

This is the native replacement for the reference `engine.observe` source path.
Dataflow/reachability/binary passes are later slices (binary belongs to
unmask-re). Judgment-free: no BP-* interpretation here — that is the compose slice.
"""

from __future__ import annotations

from unmask.scanner.observe import callgraph, dataflow
from unmask.scanner.observe.atoms import Observation
from unmask.scanner.observe.callee import observe_callee
from unmask.scanner.observe.containers import reveal
from unmask.scanner.observe.content import observe_content
from unmask.scanner.observe.inventory import FileEntry, Inventory, build_inventory
from unmask.scanner.observe.manifest import observe_manifest
from unmask.scanner.observe.supply import observe_supply
from unmask.scanner.signatures import Signatures

# Atom families whose findings dataflow can prove a path for (dropper / exfil /
# decode-exec / ransom / propagation / mitm); only files carrying one of these
# are worth an intra-file taint pass.
_DATAFLOW_FAMILIES = ("NETW", "CRED", "EXEC", "LOAD", "FSYS", "XFRM")


def _merge_revealed(inv: Inventory, target: str, reveal_dir) -> None:
    """Unpack containers under `target` and fold the revealed files into `inv`, with
    `container!member` logical paths so compose treats them as their own scope."""
    for revealed_root, origin in reveal(target, reveal_dir):
        for f in build_inventory(str(revealed_root)).files:
            inv.files.append(FileEntry(
                path=f.path, rel=f"{origin}!{f.rel}", kind=f.kind,
                language=f.language, ecosystem=f.ecosystem, size=f.size))


def observe(target: str, sigs: Signatures | None = None, *,
            reveal_dir=None) -> tuple[list[Observation], Inventory]:
    inv = build_inventory(target)
    if reveal_dir is not None:
        _merge_revealed(inv, target, reveal_dir)
    sigs = sigs or Signatures.load_vendored()

    observations: list[Observation] = []
    observations += observe_content(inv, sigs)
    observations += observe_callee(inv, sigs)
    observations += observe_manifest(inv)
    observations += observe_supply(inv)

    # Dedup identical atoms-at-a-location, then assign stable sequential ids.
    seen: set[tuple] = set()
    deduped: list[Observation] = []
    for o in observations:
        k = o.key()
        if k in seen:
            continue
        seen.add(k)
        deduped.append(o)
    for i, o in enumerate(deduped, start=1):
        o.id = f"obs-{i}"

    # Native dataflow + reachability. Intra-file taint runs only on files that
    # carry a dataflow-relevant atom (a payload family); reachability spans the
    # whole package's JS/TS/Python call graph. The compose layer consumes these
    # to upgrade same-file co-occurrence to a proven path.
    relevant = {o.path for o in deduped
                if (o.atom or "").split(".")[0] in _DATAFLOW_FAMILIES}
    inv.dataflow = dataflow.analyze_inventory(inv, only_paths=relevant)
    inv.reachability = callgraph.analyze(inv)
    return deduped, inv

"""Assemble the observe passes into `observe(target) -> (observations, inventory)`.

    inventory  ->  content + callee + manifest + supply  ->  dedup  ->  atoms

This is the native replacement for the reference `engine.observe` source path.
Dataflow/reachability/binary passes are later slices (binary belongs to
unmask-re). Judgment-free: no BP-* interpretation here — that is the compose slice.
"""

from __future__ import annotations

from unmask.scanner.observe.atoms import Observation
from unmask.scanner.observe.callee import observe_callee
from unmask.scanner.observe.content import observe_content
from unmask.scanner.observe.inventory import Inventory, build_inventory
from unmask.scanner.observe.manifest import observe_manifest
from unmask.scanner.observe.supply import observe_supply
from unmask.scanner.signatures import Signatures


def observe(target: str, sigs: Signatures | None = None) -> tuple[list[Observation], Inventory]:
    inv = build_inventory(target)
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
    return deduped, inv

"""The transform seam: core ↔ the RE toolset.

Core plans transforms for artifacts it can't read (obfuscated source, binaries),
hands them to duck-typed providers (`unmask-re`, driving skillpacks), and folds what
they recover — derived source it rescans, atoms it ingests — back into the scan. With
no provider registered the seam is inert and binaries stay an honest blind spot.
"""

from __future__ import annotations

from unmask.transform.contract import (
    ArtifactRef,
    DerivedSource,
    EmittedAtom,
    TransformProvider,
    TransformResult,
)
from unmask.transform.engine import FoldOutcome, fold_results, run_transform_pass
from unmask.transform.ingest import ingest_atoms
from unmask.transform.plan import TransformRequest, plan_transforms

__all__ = [
    "ArtifactRef", "DerivedSource", "EmittedAtom", "TransformProvider", "TransformResult",
    "FoldOutcome", "fold_results", "run_transform_pass",
    "ingest_atoms", "TransformRequest", "plan_transforms",
]

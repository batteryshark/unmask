"""muster — a ledgered investigation runtime.

A durable, coverage-gated, resumable work-graph runtime with bounded adaptive model
steps. muster owns the SPINE (run identity + on-disk layout, the SQLite ledger, the
graph runner with the work-queue drain, resume, and the lead / adversarial-verify /
durable-question patterns). A consumer registers its DOMAIN — its tables, nodes, work
handlers, and coverage predicate — via composition, never by muster knowing about the
domain (see docs/investigation-engine-seam.md).

Extraction in progress: slices 1 (run identity + paths) and 2 (the ledger core) are
here; the graph scaffolding follows.
"""

from __future__ import annotations

from muster.graph import (
    GraphDeps,
    GraphState,
    WorkDispatcher,
    ask,
    atomic_write,
    enter,
)
from muster.ledger import Ledger, SCHEMA_VERSION, new_id, stable_key
from muster.paths import (
    RunPaths,
    compute_project_id,
    compute_run_id,
    new_run_paths,
    resolve_run_dir,
)

__all__ = [
    "Ledger", "SCHEMA_VERSION", "new_id", "stable_key",
    "GraphState", "GraphDeps", "WorkDispatcher", "atomic_write", "enter", "ask",
    "RunPaths", "compute_project_id", "compute_run_id", "new_run_paths", "resolve_run_dir",
]

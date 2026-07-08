"""muster — a ledgered investigation runtime.

A durable, coverage-gated, resumable work-graph runtime with bounded adaptive model
steps. muster owns the SPINE (run identity + on-disk layout, the SQLite ledger, the
graph runner with the work-queue drain, resume, and the lead / adversarial-verify /
durable-question patterns). A consumer registers its DOMAIN — its tables, nodes, work
handlers, and coverage predicate — via composition, never by muster knowing about the
domain (see docs/investigation-engine-seam.md).

Extraction in progress: slice 1 (run identity + paths) is here; the ledger core and
graph scaffolding follow.
"""

from __future__ import annotations

from muster.paths import (
    RunPaths,
    compute_project_id,
    compute_run_id,
    new_run_paths,
    resolve_run_dir,
)

__all__ = [
    "RunPaths", "compute_project_id", "compute_run_id", "new_run_paths", "resolve_run_dir",
]

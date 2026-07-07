"""Top-level run orchestration: set up storage + ledger, drive the graph."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from unmask.config import MCDConfig
from unmask.graph import InitializeRun, MCDGraphDeps, MCDGraphState, build_graph
from unmask.ledger import LedgerStore
from unmask.providers import discover_providers
from unmask.storage.paths import (
    RunPaths, compute_project_id, compute_run_id, new_run_paths, resolve_run_dir,
)


@dataclass
class RunResult:
    run_id: str
    project_id: str
    run_dir: str
    status: str
    disposition: str
    finding_count: int
    blocked_binaries: int
    report_paths: dict


def _drive(paths: RunPaths, config: MCDConfig, target_path: Path, ledger: LedgerStore,
           *, review_model=None, resume: bool = False) -> RunResult:
    """Run the graph over an already-created run and close the ledger."""
    toolchain = discover_providers()
    state = MCDGraphState(
        run_id=paths.run_id, project_id=paths.project_id, run_dir=paths.run_dir,
        db_path=paths.db_path, target_path=target_path,
        max_iterations=config.max_iterations,
    )
    deps = MCDGraphDeps(ledger=ledger, config=config, paths=paths, toolchain=toolchain,
                        review_model=review_model, resume=resume)
    graph = build_graph()
    try:
        result = graph.run_sync(inputs=InitializeRun(), state=state, deps=deps)
    except Exception as exc:
        ledger.finish_run(paths.run_id, "failed", error=repr(exc))
        raise
    finally:
        ledger.close()

    return RunResult(
        run_id=result["runId"], project_id=result["projectId"],
        run_dir=result["runDir"], status=result["status"],
        disposition=result["disposition"], finding_count=result["findingCount"],
        blocked_binaries=result["blockedBinaries"], report_paths=result["reportPaths"],
    )


def run_mcd(target: str, config: MCDConfig | None = None, *, review_model=None) -> RunResult:
    config = config or MCDConfig()
    target_path = Path(target).resolve()
    if not target_path.exists():
        raise FileNotFoundError(f"target does not exist: {target_path}")
    target_root = target_path if target_path.is_dir() else target_path.parent

    project_id, _meta = compute_project_id(target_root)
    run_id, run_hash = compute_run_id(project_id, target_path, config.config_hash())
    paths = new_run_paths(config.storage_root, project_id, run_id, run_hash)

    ledger = LedgerStore(paths.db_path)
    ledger.create_run(
        run_id=run_id, project_id=project_id, target_path=target_path,
        target_root=target_root, storage_root=Path(config.storage_root).resolve(),
        run_dir=paths.run_dir, config_json=json.dumps(config.__dict__),
    )
    return _drive(paths, config, target_path, ledger, review_model=review_model)


def resume_mcd(run_dir: str, *, review_model=None) -> RunResult:
    """Re-drive an existing run from its ledger — reconstructing the original config and
    target from the DB, clearing the derived tables for a clean re-record, and reusing
    the run dir's on-disk caches (fetched bytes) so external work isn't redone."""
    paths = resolve_run_dir(run_dir)
    ledger = LedgerStore(paths.db_path)
    row = ledger.get_run(paths.run_id)
    if row is None:
        ledger.close()
        raise ValueError(f"no run {paths.run_id!r} recorded in {paths.db_path}")
    prior_status = row["status"]
    config = MCDConfig(**json.loads(row["config_json"] or "{}"))
    target_path = Path(row["target_path"])
    if not target_path.exists():
        ledger.close()
        raise FileNotFoundError(f"target no longer exists: {target_path}")

    ledger.reset_run_derived(paths.run_id)
    ledger.create_run(  # reset status to running, preserving identity + config
        run_id=paths.run_id, project_id=paths.project_id, target_path=target_path,
        target_root=Path(row["target_root"]), storage_root=Path(row["storage_root"]),
        run_dir=paths.run_dir, config_json=row["config_json"],
    )
    ledger.event(paths.run_id, "ResumeRun", "note", {"resumedFrom": prior_status})
    return _drive(paths, config, target_path, ledger, review_model=review_model, resume=True)


def status_of(run_dir: str) -> dict:
    """Cheap status read from run.json (no DB open needed)."""
    paths = resolve_run_dir(run_dir)
    return json.loads(paths.run_json.read_text(encoding="utf-8"))

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


def resume_mcd(run_dir: str, *, review_model=None, answers: dict | None = None) -> RunResult:
    """Re-drive an existing run from its ledger — reconstructing the original config and
    target from the DB, clearing the derived tables for a clean re-record, and reusing
    the run dir's on-disk caches (fetched bytes) so external work isn't redone. ``answers``
    (question id → answer) resolves questions a `needs_input` run left pending."""
    paths = resolve_run_dir(run_dir)
    ledger = LedgerStore(paths.db_path)
    row = ledger.get_run(paths.run_id)
    if row is None:
        ledger.close()
        raise ValueError(f"no run {paths.run_id!r} recorded in {paths.db_path}")
    prior_status = row["status"]
    try:
        config = MCDConfig(**json.loads(row["config_json"] or "{}"))
    except (ValueError, TypeError) as exc:  # malformed json / config schema drift
        ledger.close()
        raise ValueError(
            f"cannot reconstruct config for run {paths.run_id!r} (schema drift or "
            f"corruption): {exc}") from exc
    target_path = Path(row["target_path"])
    if not target_path.exists():
        ledger.close()
        raise FileNotFoundError(f"target no longer exists: {target_path}")

    # Inject answers to pending questions BEFORE reset — the answers table survives the
    # reset, so a re-asked question finds its answer and the asking node proceeds.
    for qid, answer in (answers or {}).items():
        ledger.record_answer(paths.run_id, qid, answer)

    ledger.reset_run_derived(paths.run_id)
    ledger.create_run(  # reset status to running, preserving identity + config
        run_id=paths.run_id, project_id=paths.project_id, target_path=target_path,
        target_root=Path(row["target_root"]), storage_root=Path(row["storage_root"]),
        run_dir=paths.run_dir, config_json=row["config_json"],
    )
    ledger.event(paths.run_id, "ResumeRun", "note",
                 {"resumedFrom": prior_status, "answers": len(answers or {})})
    return _drive(paths, config, target_path, ledger, review_model=review_model, resume=True)


def project_rollup(run_dir: str) -> dict:
    """Aggregate OPEN WORK across every run in a project — the orchestrator's
    'what's covered, what's outstanding' read. Given any run dir, walks its sibling
    runs and rolls up per-run status/disposition + the open items (pending questions,
    blocked binaries, open leads). This is what lets an orchestrator pivot on the whole
    investigation rather than one sweep."""
    rd = Path(run_dir).resolve()
    project_dir = rd.parents[1]  # .../projects/<project-id>/runs/<run> -> .../projects/<pid>
    project_id = project_dir.name
    runs: list[dict] = []
    totals = {"pendingQuestions": 0, "blockedBinaries": 0, "openLeads": 0, "needsInput": 0}
    for run_json in sorted(project_dir.glob("runs/*/run.json")):
        try:
            meta = json.loads(run_json.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        entry = {"runId": meta.get("runId"), "status": meta.get("status"),
                 "disposition": meta.get("disposition"), "runDir": str(run_json.parent)}
        db = run_json.parent / "run.db"
        rid = meta.get("runId")
        if db.is_file() and rid:
            led = LedgerStore(str(db))
            try:
                entry["pendingQuestions"] = led.count_pending_questions(rid)
                entry["blockedBinaries"] = led.count_work_items(rid, operation="scan-binary", status="blocked")
                entry["openLeads"] = led.count_work_items(rid, operation="lead", status="deferred")
            finally:
                led.close()
            for k in ("pendingQuestions", "blockedBinaries", "openLeads"):
                totals[k] += entry.get(k, 0)
            if meta.get("status") == "needs_input":
                totals["needsInput"] += 1
        runs.append(entry)
    return {"projectId": project_id, "runCount": len(runs), "open": totals, "runs": runs}


def pending_questions_of(run_dir: str) -> list[dict]:
    """The questions a `needs_input` run left pending — what an orchestrator answers,
    then passes back to `resume_mcd(answers=...)`."""
    paths = resolve_run_dir(run_dir)
    ledger = LedgerStore(paths.db_path)
    try:
        return ledger.pending_questions(paths.run_id)
    finally:
        ledger.close()


def status_of(run_dir: str) -> dict:
    """Cheap status read from run.json (no DB open needed)."""
    paths = resolve_run_dir(run_dir)
    return json.loads(paths.run_json.read_text(encoding="utf-8"))

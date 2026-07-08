"""Project/run identity and the on-disk run directory layout (muster core).

Layout:

    <storage_root>/
      projects/
        <project-id>/            a project = repeated sweeps of one target
          runs/
            <started>-<run-hash>/
              run.json          small status file for cheap discovery/resume
              run.db            authoritative per-run SQLite ledger
              reports/          rendered outputs
              artifacts/        run artifacts
              fetched/  logs/  tmp/

One SQLite database per run, next to the outputs it describes: no write contention
between concurrent runs, trivial archival, resume is just a path. Project identity is
content-derived (git root/remote or target path) so repeated sweeps of one target group
under the same project.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

_SLUG_RE = re.compile(r"[^a-zA-Z0-9._-]+")


def _sanitize(name: str) -> str:
    slug = _SLUG_RE.sub("-", name).strip("-._")
    return (slug or "target")[:48]


def _git_info(target_root: Path) -> tuple[str | None, str | None]:
    """(git_root, git_remote_origin_url) or (None, None); never raises."""
    try:
        root = subprocess.run(
            ["git", "-C", str(target_root), "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=5,
        )
        if root.returncode != 0:
            return None, None
        git_root = root.stdout.strip()
        remote = subprocess.run(
            ["git", "-C", git_root, "config", "--get", "remote.origin.url"],
            capture_output=True, text=True, timeout=5,
        )
        return git_root, (remote.stdout.strip() or None)
    except Exception:
        return None, None


def compute_project_id(target_root: Path) -> tuple[str, dict]:
    """Stable id grouping repeated scans of the same target.

    Returns (project_id, meta) where meta carries slug/hash/git for the index.
    """
    target_root = target_root.resolve()
    git_root, git_remote = _git_info(target_root)
    slug = _sanitize(Path(git_root).name if git_root else target_root.name)
    seed = "\n".join([str(target_root), git_root or "", git_remote or ""])
    project_hash = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12]
    project_id = f"{slug}_{project_hash}"
    return project_id, {
        "project_slug": slug,
        "project_hash": project_hash,
        "git_root": git_root,
        "git_remote": git_remote,
    }


def compute_run_id(project_id: str, target_path: Path, config_hash: str) -> tuple[str, str]:
    """(run_id, run_hash), unique per invocation."""
    started = datetime.now(timezone.utc)
    compact = started.strftime("%Y%m%d-%H%M%S")
    nonce = os.urandom(6).hex()
    seed = "".join([project_id, str(target_path.resolve()), config_hash, compact, nonce])
    run_hash = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12]
    return f"run_{started.strftime('%Y%m%d_%H%M%S')}_{run_hash}", run_hash


@dataclass
class RunPaths:
    storage_root: Path
    project_id: str
    run_id: str
    run_dir: Path

    @property
    def db_path(self) -> Path:
        return self.run_dir / "run.db"

    @property
    def run_json(self) -> Path:
        return self.run_dir / "run.json"

    @property
    def reports_dir(self) -> Path:
        return self.run_dir / "reports"

    @property
    def tree_dir(self) -> Path:
        return self.run_dir / "artifacts" / "tree"

    def ensure(self) -> "RunPaths":
        for d in (self.run_dir, self.reports_dir, self.tree_dir,
                  self.run_dir / "tool-output", self.run_dir / "fetched",
                  self.run_dir / "logs", self.run_dir / "tmp"):
            d.mkdir(parents=True, exist_ok=True)
        return self


def new_run_paths(storage_root: str | Path, project_id: str, run_id: str, run_hash: str) -> RunPaths:
    storage_root = Path(storage_root).resolve()
    started_compact = run_id.split("_")[1] + "-" + run_id.split("_")[2][:6] if run_id.count("_") >= 2 else run_id
    run_dirname = f"{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{run_hash}"
    run_dir = storage_root / "projects" / project_id / "runs" / run_dirname
    return RunPaths(storage_root, project_id, run_id, run_dir).ensure()


def resolve_run_dir(run_dir: str | Path) -> RunPaths:
    """Reopen an existing run directory (for resume/status/report)."""
    run_dir = Path(run_dir).resolve()
    import json

    meta = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    return RunPaths(
        storage_root=run_dir.parents[3],
        project_id=meta["projectId"],
        run_id=meta["runId"],
        run_dir=run_dir,
    )

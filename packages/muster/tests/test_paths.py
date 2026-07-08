"""muster.paths — run/project identity + on-disk layout, tested standalone."""

from __future__ import annotations

import json
from pathlib import Path

from muster import (
    compute_project_id, compute_run_id, new_run_paths, resolve_run_dir,
)


def test_project_id_stable_and_content_derived(tmp_path):
    pid1, meta = compute_project_id(tmp_path)
    pid2, _ = compute_project_id(tmp_path)
    assert pid1 == pid2                                     # stable across calls
    assert meta["project_hash"] and meta["project_slug"]
    sub = tmp_path / "sub"
    sub.mkdir()
    pid3, _ = compute_project_id(sub)
    assert pid3 != pid1                                     # different target → different id


def test_run_id_unique_per_invocation():
    a, ha = compute_run_id("p", Path("/t"), "cfg")
    b, hb = compute_run_id("p", Path("/t"), "cfg")
    assert a != b and ha != hb                              # nonce + timestamp keep it unique


def test_new_run_paths_layout_and_resolve_round_trip(tmp_path):
    pid, _ = compute_project_id(tmp_path)
    rid, rhash = compute_run_id(pid, tmp_path, "cfg")
    paths = new_run_paths(tmp_path, pid, rid, rhash)
    assert paths.run_dir.is_dir() and paths.reports_dir.is_dir()
    assert paths.db_path == paths.run_dir / "run.db"
    assert paths.run_json == paths.run_dir / "run.json"
    # resolve_run_dir reopens the run from its directory alone (via run.json)
    paths.run_json.write_text(json.dumps({"runId": rid, "projectId": pid}), encoding="utf-8")
    reopened = resolve_run_dir(paths.run_dir)
    assert reopened.run_id == rid and reopened.project_id == pid
    assert reopened.run_dir == paths.run_dir

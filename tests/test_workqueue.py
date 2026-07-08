"""The ProcessWorkQueue branching loop.

The graph leases actionable ledger work items one per pass and self-loops until the
queue drains, so N discovered items are worked off across N iterations (visible in
graph_events) rather than assumed done inline. Binary-artifact disposition is the first
handler: blocked (nothing installed) or deferred (a provider is present but couldn't
open it up).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from unmask import MCDConfig, run_mcd


def _binpkg(tmp_path, n):
    d = tmp_path / "pkg"
    d.mkdir()
    for i in range(n):
        (d / f"b{i}.so").write_bytes(b"\x7fELF" + b"\x00" * 40)
    return d


def _db(run_dir):
    c = sqlite3.connect(Path(run_dir) / "run.db")
    c.row_factory = sqlite3.Row
    return c


def _bin_status_counts(conn):
    return {r["status"]: r["c"] for r in conn.execute(
        "select status, count(*) c from work_items where operation='scan-binary' group by status")}


def _pwq_enters(conn):
    return conn.execute(
        "select count(*) c from graph_events where node='ProcessWorkQueue' and event='enter'"
    ).fetchone()["c"]


def test_loop_drains_binaries_across_iterations_no_provider(tmp_path, monkeypatch):
    import unmask.run as runmod
    from unmask.providers import ToolchainStatus
    monkeypatch.setattr(runmod, "discover_providers", lambda: ToolchainStatus())  # nothing installed

    result = run_mcd(str(_binpkg(tmp_path, 3)), MCDConfig(storage_root=str(tmp_path / ".mcd")))
    conn = _db(result.run_dir)
    try:
        assert _bin_status_counts(conn) == {"blocked": 3}
        assert result.blocked_binaries == 3
        # one pass per item + a final drain pass that finds the queue empty
        assert _pwq_enters(conn) >= 4
        # the loop left nothing actionable
        assert conn.execute(
            "select count(*) c from work_items where status in ('queued','leased')"
        ).fetchone()["c"] == 0
    finally:
        conn.close()


def test_loop_defers_binaries_when_provider_present(tmp_path):
    # Default toolchain here has the unmask-re stub (advertises binary caps) -> has_re,
    # but no working transform -> the loop defers rather than blocks.
    result = run_mcd(str(_binpkg(tmp_path, 2)), MCDConfig(storage_root=str(tmp_path / ".mcd")))
    conn = _db(result.run_dir)
    try:
        counts = _bin_status_counts(conn)
        assert counts.get("deferred") == 2 and "blocked" not in counts
        assert result.blocked_binaries == 0
    finally:
        conn.close()


def test_source_only_target_drains_immediately(tmp_path):
    # No binaries -> the loop finds an empty queue on its first pass and renders.
    (tmp_path / "a.py").write_text("import os\nos.getcwd()\n")
    result = run_mcd(str(tmp_path), MCDConfig(storage_root=str(tmp_path / ".mcd")))
    conn = _db(result.run_dir)
    try:
        assert _pwq_enters(conn) == 1  # single drain pass, no work
        assert result.status == "completed"
    finally:
        conn.close()

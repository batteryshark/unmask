"""`unmask` command-line interface.

First-cut surface (docs/design.md "Public Surfaces"): run, tree, tools doctor,
status, report, list, version. Network/decompiler/approval subcommands arrive
with their milestones.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


_ROLE_ALIASES = {"leads": "proposer", "review": "reviewer", "verify": "verifier"}


def _parse_models(spec: str | None) -> dict:
    """Parse `role=[provider:]model,...` into a role→spec map (roles: reviewer/verifier/
    proposer/qa; friendly aliases leads/review/verify accepted)."""
    out: dict[str, str] = {}
    for pair in (spec or "").split(","):
        role, sep, model = pair.strip().partition("=")
        if sep and model.strip():
            out[_ROLE_ALIASES.get(role.strip(), role.strip())] = model.strip()
    return out


def _cmd_run(args: argparse.Namespace) -> int:
    import os

    from unmask.config import MCDConfig
    from unmask.run import run_mcd

    # --model overrides the review model (parsed as [provider:]model_id). If the
    # user passes --model we set the env vars ReviewModelConfig reads, so the same
    # code path works for CLI and API callers.
    if getattr(args, "model", None):
        spec = args.model.split(":", 1)
        if len(spec) == 2:
            os.environ.setdefault("UNMASK_REVIEW_PROVIDER", spec[0])
            os.environ.setdefault("UNMASK_REVIEW_MODEL", spec[1])
        else:
            os.environ.setdefault("UNMASK_REVIEW_MODEL", spec[0])

    config = MCDConfig(
        storage_root=args.storage_root,
        scanner_root=args.scanner_root,
        sandbox=args.sandbox,
        network=args.network,
        tool_profile=args.tool_profile,
        review=args.review or args.post_report_qa != "off",  # QA needs review judgments
        verify=getattr(args, "verify", False),
        leads=getattr(args, "leads", False),
        confirm_fetch=getattr(args, "confirm_fetch", False),
        post_report_qa=args.post_report_qa,
        model=getattr(args, "model", None),
        models=_parse_models(getattr(args, "models", None)),
    )
    result = run_mcd(args.target, config)

    if args.json:
        print(json.dumps(result.__dict__, indent=2))
        return 0

    print(f"Run:        {result.run_id}")
    print(f"Project:    {result.project_id}")
    print(f"Dir:        {result.run_dir}")
    print(f"Status:     {result.status}")
    print(f"Disposition:{result.disposition!s:>12}   ({result.finding_count} finding(s))")
    if result.blocked_binaries:
        print(f"Blind spot: {result.blocked_binaries} binary artifact(s) not deeply "
              f"analysed — install unmask-re")
    print(f"Report:     {result.report_paths['html']}")
    print(f"Resume:     unmask status --run-dir {result.run_dir}")
    return 0 if result.status == "completed" else 1


def _cmd_tree(args: argparse.Namespace) -> int:
    from unmask.inventory.tree import build_tree

    tree = build_tree(args.target, max_depth=args.max_depth, max_entries=args.max_entries,
                      include_hidden=args.include_hidden)
    if args.format == "json":
        print(json.dumps(tree.json, indent=2))
    else:
        print(tree.text)
        s = tree.summary
        print(f"\n{s['files']} files, {s['directories']} dirs, "
              f"{s['binaryArtifacts']} binary artifact(s)"
              f"{' (truncated)' if s['truncated'] else ''}")
    return 0


def _cmd_tools(args: argparse.Namespace) -> int:
    from unmask.providers import discover_providers

    if args.tools_cmd != "doctor":
        print("usage: unmask tools doctor", file=sys.stderr)
        return 2
    status = discover_providers()
    rep = status.to_report()
    if args.json:
        print(json.dumps(rep, indent=2))
        return 0
    print(f"RE providers installed: {rep['reProvidersInstalled']}")
    if rep["providers"]:
        for p in rep["providers"]:
            mark = "!" if p["error"] else "+"
            print(f"  [{mark}] {p['id']}: {', '.join(p['capabilities']) or '(no caps)'}"
                  f"{'  ERROR: ' + p['error'] if p['error'] else ''}")
    else:
        print("  (none registered)")
    if rep["hint"]:
        print(f"\n{rep['hint']}")
    return 0


def _cmd_resume(args: argparse.Namespace) -> int:
    from unmask.run import resume_mcd

    answers = {}
    for pair in (args.answer or []):
        qid, sep, val = pair.partition("=")
        if sep:
            answers[qid.strip()] = val.strip()
    result = resume_mcd(args.run_dir, answers=answers or None)
    if args.json:
        print(json.dumps(result.__dict__, indent=2))
        return 0
    print(f"Resumed:    {result.run_id}")
    print(f"Dir:        {result.run_dir}")
    print(f"Status:     {result.status}")
    print(f"Disposition:{result.disposition!s:>12}   ({result.finding_count} finding(s))")
    print(f"Report:     {result.report_paths['html']}")
    return 0 if result.status == "completed" else 1


def _cmd_questions(args: argparse.Namespace) -> int:
    from unmask.run import pending_questions_of

    pending = pending_questions_of(args.run_dir)
    if args.json:
        print(json.dumps(pending, indent=2))
        return 0
    if not pending:
        print("(no pending questions)")
        return 0
    for q in pending:
        opts = f"  [{'/'.join(q['options'])}]" if q.get("options") else ""
        print(f"{q['id']}  ({q['kind']}){opts}\n  {q['prompt']}")
    print(f"\nAnswer with: unmask resume --run-dir {args.run_dir} --answer <id>=<value>")
    return 0


def _cmd_project(args: argparse.Namespace) -> int:
    from unmask.run import project_rollup

    roll = project_rollup(args.run_dir)
    if args.json:
        print(json.dumps(roll, indent=2))
        return 0
    o = roll["open"]
    print(f"Project:  {roll['projectId']}   ({roll['runCount']} run(s))")
    print(f"Open:     {o['pendingQuestions']} question(s), {o['blockedBinaries']} blocked "
          f"binary, {o['openLeads']} open lead(s), {o['needsInput']} needs-input run(s)")
    for r in roll["runs"]:
        print(f"  {r.get('status', '?'):11} {r.get('disposition', ''):11} {r.get('runId', '')}")
    return 0


def _cmd_mcp(args: argparse.Namespace) -> int:
    from unmask.mcp_server import main as mcp_main

    return mcp_main()


def _cmd_status(args: argparse.Namespace) -> int:
    from unmask.run import status_of

    print(json.dumps(status_of(args.run_dir), indent=2))
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    from unmask.storage.paths import resolve_run_dir

    paths = resolve_run_dir(args.run_dir)
    fp = paths.reports_dir / f"report.{ 'md' if args.format == 'md' else args.format }"
    if not fp.is_file():
        print(f"no {args.format} report at {fp}", file=sys.stderr)
        return 1
    print(fp.read_text(encoding="utf-8"))
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    root = Path(args.storage_root) / "projects"
    if not root.is_dir():
        print("(no runs)")
        return 0
    for run_json in sorted(root.glob("*/runs/*/run.json")):
        try:
            meta = json.loads(run_json.read_text(encoding="utf-8"))
        except Exception:
            continue
        print(f"{meta.get('status', '?'):9} {meta.get('runId', '?'):40} "
              f"{meta.get('disposition', '')}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="unmask", description="Malicious Code Detection")
    p.add_argument("--version", action="store_true", help="print version and exit")
    sub = p.add_subparsers(dest="cmd")

    run = sub.add_parser("run", help="scan a target")
    run.add_argument("target")
    run.add_argument("--storage-root", default=".mcd")
    run.add_argument("--scanner-root", default="auto",
                     help="path to a parallax-goalpacks checkout (engine + mcd_lens)")
    run.add_argument("--sandbox", default="auto",
                     choices=["auto", "subprocess", "openshell", "none"])
    run.add_argument("--network", default="offline",
                     choices=["offline", "registry", "fetch-only", "dynamic"],
                     help="fetch-only: download URLs the target executes (curl|sh) as "
                          "evidence and rescan them, SSRF-guarded, never run (default offline)")
    run.add_argument("--tool-profile", default="static",
                     choices=["static", "source", "binary", "full"])
    run.add_argument("--review", action="store_true",
                     help="agentic adjudication of findings (needs unmask[review] + UNMASK_REVIEW_*)")
    run.add_argument("--verify", action="store_true",
                     help="adversarially verify review downgrades before they stand (implies --review)")
    run.add_argument("--leads", action="store_true",
                     help="model-proposed adaptive leads on residue (needs a model)")
    run.add_argument("--model", default=None,
                     help="default review model as [provider:]model_id, e.g. lmstudio:qwen2.5-27b or "
                          "openai:gpt-4o (sets UNMASK_REVIEW_PROVIDER/MODEL; implies nothing without --review)")
    run.add_argument("--models", default=None,
                     help="per-role model overrides: role=[provider:]model,... e.g. "
                          "proposer=lmstudio:m3,verifier=zai:glm (roles: reviewer/verifier/proposer/qa)")
    run.add_argument("--post-report-qa", default="off", choices=["off", "rules"],
                     help="advisory rule-tuning feedback over reviewed findings (implies --review)")
    run.add_argument("--confirm-fetch", action="store_true",
                     help="gate each remote fetch on a durable question; the run finishes "
                          "needs_input, answer via `unmask questions` + `resume --answer`")
    run.add_argument("--json", action="store_true")
    run.set_defaults(func=_cmd_run)

    tree = sub.add_parser("tree", help="bounded target tree")
    tree.add_argument("target")
    tree.add_argument("--max-depth", type=int, default=4)
    tree.add_argument("--max-entries", type=int, default=2000)
    tree.add_argument("--include-hidden", action="store_true")
    tree.add_argument("--format", default="text", choices=["text", "json"])
    tree.set_defaults(func=_cmd_tree)

    tools = sub.add_parser("tools", help="toolchain / RE provider status")
    tools.add_argument("tools_cmd", choices=["doctor"])
    tools.add_argument("--json", action="store_true")
    tools.set_defaults(func=_cmd_tools)

    res = sub.add_parser("resume", help="re-drive an existing run from its ledger, "
                                        "reusing fetched content; --answer resolves questions")
    res.add_argument("--run-dir", required=True)
    res.add_argument("--answer", action="append", metavar="ID=VALUE",
                     help="answer a pending question (repeatable), e.g. --answer <id>=yes")
    res.add_argument("--json", action="store_true")
    res.set_defaults(func=_cmd_resume)

    q = sub.add_parser("questions", help="list a run's pending questions (needs_input)")
    q.add_argument("--run-dir", required=True)
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=_cmd_questions)

    proj = sub.add_parser("project", help="rollup of open work across a project's runs")
    proj.add_argument("--run-dir", required=True)
    proj.add_argument("--json", action="store_true")
    proj.set_defaults(func=_cmd_project)

    mcp = sub.add_parser("mcp", help="run the MCP server (stdio) exposing scan/resume/report")
    mcp.set_defaults(func=_cmd_mcp)

    st = sub.add_parser("status", help="run status from run.json")
    st.add_argument("--run-dir", required=True)
    st.set_defaults(func=_cmd_status)

    rep = sub.add_parser("report", help="print a rendered report")
    rep.add_argument("--run-dir", required=True)
    rep.add_argument("--format", default="md", choices=["html", "md", "json"])
    rep.set_defaults(func=_cmd_report)

    ls = sub.add_parser("list", help="list runs under a storage root")
    ls.add_argument("--storage-root", default=".mcd")
    ls.set_defaults(func=_cmd_list)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.version:
        from unmask import __version__
        print(f"unmask {__version__}")
        return 0
    if not getattr(args, "cmd", None):
        parser.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

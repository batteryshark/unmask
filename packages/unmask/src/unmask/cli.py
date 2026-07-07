"""`mcd` command-line interface.

First-cut surface (docs/design.md "Public Surfaces"): run, tree, tools doctor,
status, report, list, version. Network/decompiler/approval subcommands arrive
with their milestones.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _cmd_run(args: argparse.Namespace) -> int:
    from unmask.config import MCDConfig
    from unmask.run import run_mcd

    config = MCDConfig(
        storage_root=args.storage_root,
        scanner_root=args.scanner_root,
        sandbox=args.sandbox,
        network=args.network,
        tool_profile=args.tool_profile,
        review=args.review or args.post_report_qa != "off",  # QA needs review judgments
        post_report_qa=args.post_report_qa,
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
    print(f"Resume:     mcd status --run-dir {result.run_dir}")
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
        print("usage: mcd tools doctor", file=sys.stderr)
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

    result = resume_mcd(args.run_dir)
    if args.json:
        print(json.dumps(result.__dict__, indent=2))
        return 0
    print(f"Resumed:    {result.run_id}")
    print(f"Dir:        {result.run_dir}")
    print(f"Status:     {result.status}")
    print(f"Disposition:{result.disposition!s:>12}   ({result.finding_count} finding(s))")
    print(f"Report:     {result.report_paths['html']}")
    return 0 if result.status == "completed" else 1


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
    p = argparse.ArgumentParser(prog="mcd", description="Malicious Code Detection")
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
    run.add_argument("--post-report-qa", default="off", choices=["off", "rules"],
                     help="advisory rule-tuning feedback over reviewed findings (implies --review)")
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
                                        "reusing fetched content")
    res.add_argument("--run-dir", required=True)
    res.add_argument("--json", action="store_true")
    res.set_defaults(func=_cmd_resume)

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

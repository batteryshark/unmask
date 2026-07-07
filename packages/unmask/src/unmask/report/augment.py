"""Fold unmask run/coverage sections onto the scanner's report."""

from __future__ import annotations

import json


def augment_json_report(scanner_json: str, sections: dict) -> dict:
    """Parse the scanner's report JSON and add unmask sections at top level.

    Existing assessment keys win; unmask only *adds* keys, never rewrites the
    target assessment.
    """
    try:
        obj = json.loads(scanner_json)
        if not isinstance(obj, dict):
            obj = {"assessment": obj}
    except (json.JSONDecodeError, TypeError):
        obj = {"assessmentRaw": scanner_json}
    for key, value in sections.items():
        obj.setdefault(key, value)
    obj.setdefault("generatedBy", {"tool": "unmask", "schema": "unmask/report/0.1.0"})
    return obj


def markdown_coverage_appendix(sections: dict, blocked_binaries: int) -> str:
    ledger = sections.get("ledger", {})
    cov = ledger.get("coverage", {})
    tool = sections.get("toolchain", {})
    tree = sections.get("tree", {}).get("summary", {})
    sandbox = sections.get("sandbox", {})

    lines = [
        "",
        "---",
        "",
        "## Run coverage (unmask)",
        "",
        f"- **Run:** `{ledger.get('runId', '?')}`  ",
        f"- **Project:** `{ledger.get('projectId', '?')}`  ",
        f"- **Work items:** {cov.get('workItemsTotal', 0)} total — "
        f"{cov.get('done', 0)} done, {cov.get('blocked', 0)} blocked, "
        f"{cov.get('failed', 0)} failed, {cov.get('needsReview', 0)} needs-review  ",
        f"- **Sandbox / network:** {sandbox.get('provider', '?')} / "
        f"{sandbox.get('networkMode', '?')}; executed untrusted code: "
        f"{str(sandbox.get('executedUntrustedCode', False)).lower()}  ",
        f"- **Toolchain:** profile `{tool.get('profile', '?')}`; "
        f"RE providers installed: {str(tool.get('reProvidersInstalled', False)).lower()}  ",
    ]
    if blocked_binaries:
        lines.append(
            f"- ⚠️ **Binary blind spot:** {blocked_binaries} binary artifact(s) were "
            f"**not deeply analysed** — {tool.get('hint') or 'RE tooling unavailable.'}  "
        )
    if tree:
        lines.append(
            f"- **Tree:** {tree.get('files', 0)} files / {tree.get('directories', 0)} dirs"
            f"{' (truncated)' if tree.get('truncated') else ''}  "
        )
    lines.append("")
    lines.append(
        "_These sections are run/coverage metadata added by unmask; the assessment "
        "above is the deterministic mcd_lens reading._"
    )
    lines.append("")
    return "\n".join(lines)

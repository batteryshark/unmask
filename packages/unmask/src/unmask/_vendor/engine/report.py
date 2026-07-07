"""Stage 5: Report generation (JSON for machines/agents, Markdown for humans)."""

from __future__ import annotations

import json
import uuid
from collections import Counter
from datetime import datetime, timezone

from . import __version__, SCANNER
from . import runtime as runtime_mod
from .interpret import highest_severity
from .rules import SOURCE_LANGS


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _trim_purpose(purpose: str, limit: int = 240) -> str:
    """A short stated-purpose string for the self-contained declaration block."""
    p = " ".join((purpose or "").split())
    return (p[:limit].rstrip() + "...") if len(p) > limit else p


def build(target, lens_ids, inv, observations, findings, started, mode) -> dict:
    ts = _now()
    obs_dicts = [o.to_dict(SCANNER, __version__, ts) for o in observations]
    scanned = sum(1 for f in inv.files
                  if f.lang in SOURCE_LANGS or f.name in ("package.json", "composer.json"))
    report = {
        "schemaVersion": "0.1.0",
        "scan": {
            "id": f"scan-{uuid.uuid4().hex[:12]}",
            "startedAt": started,
            "completedAt": ts,
            "scanner": SCANNER,
            "scannerVersion": __version__,
        },
        "target": {"path": inv.root, "ecosystems": sorted(inv.ecosystems)},
        "declaration": {
            "expectedCapabilities": (list(inv.expected_capabilities) or None),
            "statedPurpose": (_trim_purpose(inv.purpose) or None),
        },
        "lenses": list(lens_ids),
        "summary": {
            "filesScanned": scanned,
            "observationCount": len(obs_dicts),
            "findingCount": len(findings),
            "highestSeverity": highest_severity(findings),
        },
        "observations": obs_dicts,
        "findings": findings,
        "notes": [
            f"Observation mode: {mode}. AST = tree-sitter (high confidence); "
            f"regex-fallback observations are flagged in their ruleId and summary.",
            "Experimental prototype. Coverage is source across many languages (JS/TS, Python, "
            "Go, Rust, Java, C/C++, C#, Ruby, PHP, shell, PowerShell, and more) via tree-sitter "
            "AST with regex fallback, plus npm/PyPI/Cargo/composer manifests. Not covered: "
            "compiled binaries and managed bytecode (decompilation track), full dataflow/"
            "reachability, runtime behavior.",
            "Severity and confidence are independent. Every finding states what would disprove it.",
        ],
    }
    reach = getattr(inv, "reachability", None)
    if reach:
        report["reachability"] = reach
    bins = getattr(inv, "binaries", None) or []
    transforms = getattr(inv, "artifact_transforms", None) or []
    if transforms:
        extracted = sum(t.get("sourceMembers", 0) for t in transforms if t.get("sourceMembers"))
        containers = [t.get("container", "") for t in transforms if t.get("sourceMembers")]
        skipped = sum(t.get("skippedMembers", 0) for t in transforms)
        truncated = sum(1 for t in transforms if t.get("truncated"))
        if containers:
            report["notes"].append(
                f"Source containers: {extracted} source member(s) extracted from "
                f"{len(containers)} container artifact(s) and scanned through the normal source "
                "pipeline with stable container!member paths. Temporary extraction files were cleaned up"
                + (f"; skipped {skipped} unsupported member(s)" if skipped else "")
                + (f"; truncated {truncated} container(s)" if truncated else "")
                + ".")
        failed = [t for t in transforms if not t.get("sourceMembers") and t.get("notes")]
        if failed:
            report["notes"].append(
                "Source-container transform attempted but no supported source members were scanned: "
                + "; ".join(f"{t.get('container')}: {', '.join(t.get('notes') or [])}"
                            for t in failed[:5]))
    if bins:
        from . import binary as binary_mod
        binary_mod.annotate_source_drift(bins, obs_dicts, inv.root)
    report["binaries"] = bins  # structured inventory (the notes below are the human-readable view)
    report["dynamicVerification"] = runtime_mod.build_status(findings)
    report["notes"].append(runtime_mod.coverage_note())
    if bins:
        decomp = Counter((b.get("decompilation") or {}).get("status", "unknown") for b in bins)
        drifted = sum(1 for b in bins if (b.get("sourceDrift") or {}).get("indicators"))
        transformed_bins = [
            b for b in bins
            if "source-container-transform" in ((b.get("analysisDepth") or {}).get("defaultMethods") or [])
        ]
        string_bins = [b for b in bins if b not in transformed_bins]
        report["notes"].append(
            f"Binary artifacts: {len(bins)} compiled/binary file(s) triaged "
            f"({len(transformed_bins)} source-container transform, {len(string_bins)} "
            "inventory/string/structure triage; never executed). "
            "Deep behavior was not analyzed; managed/native decompilation remains a blind spot "
            "unless an explicit opt-in provider review is run.")
        report["notes"].append(
            "Binary depth: default scan is source-container transform where explicitly recorded, "
            "otherwise inventory/strings/structure/imports only; "
            "decompilation provider status is recorded per artifact but no decompiler ran. "
            f"Decompilation statuses: {', '.join(f'{k}={v}' for k, v in sorted(decomp.items()))}. "
            f"Source-drift scaffolding flagged {drifted} artifact(s).")
        for b in bins[:20]:
            if b.get("error"):
                report["notes"].append(f"  binary {b['path']}: unreadable ({b['error']})")
            else:
                depth = (b.get("analysisDepth") or {}).get("status", "unknown-depth")
                dec = (b.get("decompilation") or {}).get("status", "unknown")
                drift = (b.get("sourceDrift") or {}).get("indicators") or []
                report["notes"].append(
                    f"  binary {b['path']}: {b['format']}, sha256 {b['sha256'][:16]}..., "
                    f"{b['bytes']} bytes, {b['stringObservations']} string observation(s)"
                    f", depth={depth}, decompilation={dec}"
                    + (f", drift={','.join(drift[:3])}" if drift else "")
                    + (", truncated" if b.get("truncated") else ""))
        if len(bins) > 20:
            report["notes"].append(f"  (+{len(bins) - 20} more binary artifacts)")
    from . import enrichment as enrichment_mod
    report["enrichmentProviders"] = enrichment_mod.provider_status(report)
    for note in enrichment_mod.provider_notes(report):
        if note not in report["notes"]:
            report["notes"].append(note)
    return report


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2)


def _obs_index(report):
    return {o["id"]: o for o in report["observations"]}


def render_markdown(report: dict) -> str:
    idx = _obs_index(report)
    s = report["summary"]
    L = []
    L.append("# Parallax scan report\n")
    L.append(f"**Target:** `{report['target']['path']}`  ")
    L.append(f"**Ecosystems:** {', '.join(report['target']['ecosystems']) or 'none detected'}  ")
    L.append(f"**Lenses:** {', '.join(report['lenses'])}  ")
    L.append(f"**Scanner:** {report['scan']['scanner']} {report['scan']['scannerVersion']}  ")
    L.append(
        f"**Observations:** {s['observationCount']} · **Findings:** {s['findingCount']} · "
        f"**Highest severity:** {s['highestSeverity']}\n"
    )

    # Capability map (when the capability lens ran): the affordance matrix.
    cap = [f for f in report["findings"]
           if f["lens"] == "capability" and f.get("composition", "").startswith("CAP-")]
    profile = next((f for f in report["findings"] if f.get("composition") == "CR-PROFILE"), None)
    if cap:
        L.append("## Capability surface (blast-radius map)\n")
        L.append("| Surface | Blast radius | Confidence |")
        L.append("|---|---|---|")
        for f in cap:
            L.append(
                f"| {f['title'].replace(' capable', '')} | {f['severity']} | "
                f"{f['confidence']} ({f.get('confidenceLabel', '')}) |"
            )
        if profile:
            L.append(f"\n**Overall blast radius:** {profile['severity']}")
            if profile.get("amplifiers"):
                L.append("\n**Composite blast radius (where reach multiplies):**")
                L += [f"- {a}" for a in profile["amplifiers"]]
        L.append("")

    agt = next((f for f in report["findings"] if f.get("composition") == "AR-PROFILE"), None)
    if agt:
        L.append("## Agentic risk (affordances × manipulability)\n")
        L.append(f"**Overall:** {agt['severity']} · confidence {agt['confidence']}")
        L.append(f"\n{agt['claim']}\n")
        if agt.get("amplifiers"):
            L.append("**Why it compounds:**")
            L += [f"- {a}" for a in agt["amplifiers"]]
        L.append("")

    cur = [f for f in report["findings"]
           if f["lens"] == "curiosity" and f.get("composition") != "CUR-PROFILE"]
    curprof = next((f for f in report["findings"] if f.get("composition") == "CUR-PROFILE"), None)
    if cur or curprof:
        L.append("## Curiosity (what's surprising here)\n")
        if curprof:
            L.append(curprof["claim"] + "\n")
        for f in cur:
            L.append(f"- **{f['title']}** · {f['confidence']} confidence")
        L.append("")

    L.append("## Findings\n")
    if not report["findings"]:
        L.append("_No lens findings. Observations below are still worth reading._\n")
    for f in report["findings"]:
        comp = f" · {f['composition']}" if f.get("composition") else ""
        L.append(f"### [{f['severity'].upper()}] {f['title']}  ({f['lens']}{comp})")
        L.append(
            f"Confidence: **{f['confidence']} ({f.get('confidenceLabel','')})**. "
            f"Severity and confidence are independent.\n"
        )
        L.append(f"{f['claim']}\n")
        L.append("**Evidence:**")
        for oid in f["evidence"]:
            o = idx.get(oid)
            if o:
                loc = o["location"]
                line = f":{loc.get('startLine')}" if loc.get("startLine") else ""
                L.append(f"- `{o['atom']}` {loc['path']}{line}: {o['evidence']['summary']} ({oid})")
        if f.get("amplifiers"):
            if f["lens"] in ("capability", "agentic"):
                amp_label = "What increases blast radius"
            elif f["lens"] == "curiosity":
                amp_label = "Why it's surprising"
            else:
                amp_label = "What would increase confidence"
            L.append(f"\n**{amp_label}:**")
            L += [f"- {a}" for a in f["amplifiers"]]
        L.append("\n**What would disprove this:**")
        L += [f"- {d}" for d in f["disproofCriteria"]]
        L.append("\n**Next verification:**")
        for v in f["verification"]:
            reason = f": {v['reason']}" if v.get("reason") else ""
            L.append(f"- [{v['method']}] {v['question']}{reason}")
        r = f["response"]
        tier = f"tier {r['tier']} · " if "tier" in r else ""
        L.append(f"\n**Response:** {tier}{r.get('summary','')}")
        if r.get("actions"):
            L += [f"  - {a}" for a in r["actions"]]
        L.append("")

    dyn = report.get("dynamicVerification") or {}
    if dyn:
        L.append("## Dynamic verification\n")
        L.append(f"Status: **{dyn.get('status', 'not-run')}**. {dyn.get('policy', '')}\n")
        for task in dyn.get("tasks", []):
            refs = task.get("triggeredBy", [])
            suffix = f" · requested by {len(refs)} finding(s)" if refs else ""
            L.append(f"- `{task['id']}` ({task['method']}): {task['status']}; "
                     f"approval required: {task['approvalRequired']}{suffix}")
        L.append("")

    L.append("## Observations (judgment-free)\n")
    L.append("| id | atom | conf | method | location | evidence |")
    L.append("|---|---|---|---|---|---|")
    for o in report["observations"]:
        loc = o["location"]
        line = f":{loc.get('startLine')}" if loc.get("startLine") else ""
        L.append(
            f"| {o['id']} | `{o['atom']}` | {o['confidence']} | {o['method']} | "
            f"{loc['path']}{line} | {o['evidence']['summary']} |"
        )

    providers = report.get("enrichmentProviders") or []
    if providers:
        L.append("\n## Enrichment providers\n")
        active = [p for p in providers if p.get("availability") == "active"]
        unavailable = [p for p in providers if p.get("availability") == "unavailable"]
        for p in active:
            counts = ""
            if "manifestCount" in p or "lockfileCount" in p:
                counts = f" · manifests {p.get('manifestCount', 0)}, lockfiles {p.get('lockfileCount', 0)}"
            observed = p.get("observedAt") or "scan timestamp unavailable"
            L.append(f"- **{p.get('name', p.get('id'))}** active · observedAt `{observed}` · "
                     f"ttl `{p.get('ttl', '')}`{counts}")
        if unavailable:
            L.append("- **Unavailable offline providers:** "
                     + ", ".join(f"`{p.get('id')}`" for p in unavailable))
            for p in unavailable:
                L.append(f"  - `{p.get('id')}`: {p.get('unavailableReason')}")

    L.append("\n## Coverage (honest)\n")
    for note in report["notes"]:
        L.append(f"- {note}")
    return "\n".join(L) + "\n"

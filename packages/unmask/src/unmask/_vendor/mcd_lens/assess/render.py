"""Rendering: the Markdown and self-contained HTML assessment reports."""

from __future__ import annotations

from .common import *  # noqa: F401,F403

def _sev_tag(s):
    return f"[{(s or 'informational').upper()}]"


_DECISION_PHRASE = {
    "confirm": "CONFIRMED (holds as rated)",
    "escalate": "ESCALATED (more suspicious on review)",
    "deescalate": "DE-ESCALATED (less suspicious on review)",
    "refute": "REFUTED (explained as benign)",
    "suppress": "SUPPRESSED (rule noise)",
}


def _decision_phrase(d):
    return _DECISION_PHRASE.get(d, d or "")


# After a review, order findings by what survived it: still-legitimate first
# (confirm / escalate / deescalate, and anything not reviewed), then refuted, then
# suppressed noise last. Within a group, the highest potential rating leads
# (severity, then reviewed confidence). A finding a reviewer left standing should
# never sit below a dozen it knocked down.
_REVIEW_GROUP = {"confirm": 0, "escalate": 0, "deescalate": 0, "refute": 1, "suppress": 2}


def _finding_sort_key(f):
    rv = f.get("review") or {}
    group = _REVIEW_GROUP.get(rv.get("decision"), 0)   # unreviewed stays with the legitimate
    conf = rv.get("reviewedConfidence")
    if not isinstance(conf, (int, float)):
        conf = f.get("effectiveConfidence")
    if not isinstance(conf, (int, float)):
        conf = f.get("confidence") or 0
    return (group, -_rank(f.get("severity")), -conf)


def _ordered_findings(a: dict) -> list:
    """Findings in render order. Unchanged (scan order) unless the report was
    adjudicated, in which case review outcome drives the order."""
    findings = a.get("findings", [])
    if not a.get("adjudication"):
        return findings
    return sorted(findings, key=_finding_sort_key)


def _deduped_evidence(f: dict, idx: dict) -> tuple[list, int]:
    rows = []
    seen = set()
    omitted = 0
    for oid in f.get("evidence", []):
        o = idx.get(oid)
        if not o:
            continue
        loc = o.get("location", {})
        ev = o.get("evidence", {})
        key = (o.get("atom"), loc.get("path"), loc.get("startLine"), ev.get("summary"))
        if key in seen:
            omitted += 1
            continue
        seen.add(key)
        rows.append((oid, o, loc, ev))
    return rows, omitted


def _review_md(rv: dict) -> list:
    """The reviewer's per-finding verdict as markdown lines."""
    dropped = " (dropped from the disposition)" if rv.get("excludedFromDisposition") else ""
    L = [f"**Reviewer's verdict: {_decision_phrase(rv['decision'])}** · confidence "
         f"{rv['originalConfidence']} -> {rv['reviewedConfidence']}{dropped}"]
    if rv.get("responseTier") is not None:
        xcheck = "" if rv.get("tierAgrees", True) else f" · engine tier {rv.get('engineTier')}"
        L.append(f"Response: **tier {rv['responseTier']} - {rv.get('responseTierName', '')}**{xcheck}")
    if rv.get("proximityToHarm"):
        L.append(f"_Proximity to harm:_ {rv['proximityToHarm']}")
    L.append("")
    if rv.get("justification"):
        L.append(rv["justification"] + "\n")
    for snip in rv.get("evidenceSnippets", []):
        loc = snip.get("path", "") + (f":{snip['startLine']}" if snip.get("startLine") else "")
        L.append(f"`{loc}`")
        L.append("```")
        L.append(snip.get("code", ""))
        L.append("```")
    if rv.get("disproofChecked"):
        L.append("_Disproof checked:_")
        L += [f"- {d}" for d in rv["disproofChecked"]]
    if rv.get("references"):
        L.append("_References:_ " + ", ".join(rv["references"]))
    who = rv.get("reviewer") or {}
    bits = " ".join(x for x in [who.get("backend"), who.get("model"), who.get("role")] if x)
    if bits:
        L.append(f"_(reviewed by {bits})_")
    L.append("")
    return L


def _adjudication_md(adj: dict) -> list:
    c = adj.get("counts", {})
    L = ["## Adjudication (agentic review)\n", "_" + adj.get("note", "") + "_\n"]
    who = adj.get("reviewer") or {}
    bits = " ".join(x for x in [who.get("backend"), who.get("model"), who.get("role")] if x)
    if bits:
        L.append(f"**Reviewer:** {bits}\n")
    parts = [f"{k} {c[k]}" for k in ("confirm", "escalate", "deescalate", "refute", "suppress",
                                     "unreviewed") if c.get(k)]
    L.append(("- " + " · ".join(parts)) if parts else "- no findings reviewed")
    rl = adj.get("responseLevel")
    if rl:
        L.append(f"\n**Response level:** tier {rl['tier']} - {rl['name']} ({rl['summary']})")
    if adj.get("moved"):
        L.append("\n**Findings the review moved:**")
        for m in adj["moved"]:
            L.append(f"- `{m['findingId']}` {m['decision']}: "
                     f"{m['originalConfidence']} -> {m['reviewedConfidence']}")
    if adj.get("rule"):
        L.append(f"\n_{adj['rule']}_")
    L.append("")
    return L


def _review_leads_md(leads: list[dict]) -> list:
    if not leads:
        return []
    L = ["## Review leads\n", "_Evidence-backed reasons to review that are not counted as single-file MCD findings._\n"]
    for lead in leads:
        L.append(f"### {_sev_tag(lead.get('severity'))} {lead.get('title', '')}")
        L.append(lead.get("claim", "") + "\n")
        if lead.get("evidence"):
            L.append("**Evidence chains:**")
            for ev in lead["evidence"]:
                chain = " -> ".join(f"`{c}`" for c in ev.get("chain", []))
                L.append(f"- **{', '.join(ev.get('sinkKinds', []))}** in `{ev.get('file')}` "
                         f"(`{ev.get('function')}`), from `{ev.get('entryFile')}`: {chain}")
            L.append("")
        if lead.get("verify"):
            L.append("**Verify next:**")
            L += [f"- {v}" for v in lead["verify"]]
            L.append("")
        if lead.get("disproof"):
            L.append("**What would lower confidence:**")
            L += [f"- {d}" for d in lead["disproof"]]
            L.append("")
    return L


def render_markdown(a: dict) -> str:
    s = a["summary"]
    idx = {o["id"]: o for o in a.get("observations", [])}
    L = ["# Parallax MCD assessment\n"]
    L.append(f"**Target:** `{a['target'].get('path', '')}`  ")
    L.append(f"**Ecosystems:** {', '.join(a['target'].get('ecosystems', [])) or 'none detected'}  ")
    L.append(f"**Generated from:** scan {a['generatedFrom'].get('scanId', '')}  ")
    conf = (f"{s['highestConfidence']} ({s['highestConfidenceLabel']})"
            if s.get("highestConfidence") is not None else "n/a")
    L.append(f"**MCD findings:** {s['findingCount']} · "
             f"**Highest severity:** {s['highestSeverity'] or 'none'} · "
             f"**Highest confidence:** {conf}")
    L.append("\n_Severity (how bad if real) and confidence (how sure) are independent._\n")
    if s.get("relatedFindingCount"):
        if s.get("findingCount", 0) == 0:
            L.append(f"> The scan also surfaced {s['relatedFindingCount']} finding(s) under other "
                     "lenses (not malicious-code shapes). 0 mcd findings is not a safety verdict; "
                     "review the other-lens findings for the full picture.\n")
        else:
            L.append(f"> The scan also surfaced {s['relatedFindingCount']} finding(s) under other "
                     "lenses (not malicious-code shapes); review those for that view.\n")

    adj = a.get("adjudication")
    disp = a.get("disposition")
    if adj and adj.get("reviewedDisposition"):
        rd = adj["reviewedDisposition"]
        L.append(f"## Disposition: {(rd.get('recommendation') or '').upper()} (after review)\n")
        if adj.get("dispositionChanged"):
            L.append(f"_A reviewer's adjudication changed the disposition from "
                     f"{(adj.get('engineDisposition') or '').upper()} (engine) to "
                     f"{(rd.get('recommendation') or '').upper()}. Both are kept; the engine's original "
                     "confidences are preserved on each finding._\n")
        else:
            L.append(f"_Engine disposition {(adj.get('engineDisposition') or '').upper()} held after "
                     "review._\n")
        L.append(rd.get("rationale", "") + "\n")
        if rd.get("drivers"):
            L.append("**Drivers:**")
            L += [f"- {d}" for d in rd["drivers"]]
            L.append("")
        if rd.get("thresholds"):
            L.append(f"_{rd['thresholds']}_\n")
    elif disp and disp.get("recommendation"):
        L.append(f"## Disposition: {disp['recommendation'].upper()}\n")
        L.append(disp.get("rationale", "") + "\n")
        if disp.get("drivers"):
            L.append("**Drivers:**")
            L += [f"- {d}" for d in disp["drivers"]]
            L.append("")
        if disp.get("thresholds"):
            L.append(f"_{disp['thresholds']}_\n")

    if adj:
        L += _adjudication_md(adj)

    L += _review_leads_md(a.get("reviewLeads") or [])

    enr = a.get("enrichment") or []
    if enr:
        L.append("## Enrichment\n")
        L.append("_Lens-neutral contextual facts that adjust confidence, never severity. "
                 "Each is a fact; the MCD lens reads it as amplifying or attenuating, and the "
                 "adjusted value appears as a finding's effective confidence._\n")
        providers = a.get("enrichmentProviders") or []
        if providers:
            L.append("**Provider availability:**")
            for p in [p for p in providers if p.get("availability") == "active"]:
                observed = p.get("observedAt") or "scan timestamp unavailable"
                counts = ""
                if "manifestCount" in p or "lockfileCount" in p:
                    counts = f" · manifests {p.get('manifestCount', 0)}, lockfiles {p.get('lockfileCount', 0)}"
                L.append(f"- `{p.get('id')}` active · observedAt `{observed}` · "
                         f"ttl `{p.get('ttl', '')}`{counts}")
            unavailable = [p for p in providers if p.get("availability") == "unavailable"]
            if unavailable:
                L.append("- Unavailable offline providers: "
                         + ", ".join(f"`{p.get('id')}`" for p in unavailable))
            L.append("")
        for e in enr:
            L.append(f"- **{e['id']}** ({e['effect']}): {e['fact']}")
            L.append(f"  - {e['rationale']}")
            provider = e.get("provider") or {}
            observed = e.get("observedAt") or "scan timestamp unavailable"
            L.append(f"  - Provider: `{provider.get('id', 'unknown')}` · observedAt `{observed}` · "
                     f"ttl `{e.get('ttl', '')}`")
            comps = e.get("appliesToCompositions") or []
            if comps:
                preview = ", ".join(comps[:8])
                more = f", +{len(comps) - 8} more" if len(comps) > 8 else ""
                L.append(f"  - Applies to MCD compositions: {preview}{more}")
        L.append("")

    es = a.get("executiveSummary") or {}
    reviewed_summary = _reviewed_executive_summary(a)
    summary_text = reviewed_summary or es.get("text")
    if summary_text:
        L.append("## Executive summary\n")
        L.append(summary_text)
        if reviewed_summary:
            L.append("\n_(summary reflects the adjudicated review; the original engine summary is preserved in JSON)_")
        elif es.get("author", "engine") != "engine":
            L.append(f"\n_(summary prose written by {es['author']}; the disposition above is "
                     "deterministic, set by the engine, not the model)_")
        L.append("")

    cors = a.get("correlations") or []
    if cors:
        L.append("## Correlated signals\n")
        L.append("_Findings that share a file or a network indicator, read as one story. "
                 "Co-location is corroborating context, not proven dataflow (that is the "
                 "reachability phase)._\n")
        for c in cors:
            L.append(f"### {_sev_tag(c['severity'])} {c.get('narrative', '')}")
            L.append(f"- **Findings:** {', '.join(c['memberFindingIds'])} "
                     f"({', '.join(c['compositions'])})")
            if c.get("sharedFiles"):
                L.append(f"- **Shared files:** {', '.join('`' + p + '`' for p in c['sharedFiles'])}")
            if c.get("sharedIndicators"):
                L.append(f"- **Shared indicators:** {', '.join(c['sharedIndicators'])}")
            L.append(f"- **Signals:** {', '.join(c['signalTypes'])}"
                     + (" (cross-signal)" if c.get("crossSignal") else ""))
            if c.get("insights"):
                L.append("- **Why it compounds:**")
                L += [f"  - {t}" for t in c["insights"]]
            L.append(f"- **Corroboration:** {c['corroboration']}")
            L.append("- **What would break the link:**")
            L += [f"  - {d}" for d in c["disproof"]]
            L.append("")

    reach = a.get("reachability") or {}
    xsinks = [s for s in reach.get("reachableSinks", []) if s.get("crossFile")]
    if xsinks:
        L.append("## Cross-file reachability\n")
        L.append("_MCD sinks reachable from a package entry point through the call graph, including "
                 "chains split across files that no single-file finding would show._\n")
        for sink in xsinks:
            L.append(f"- **{', '.join(sink['sinkKinds'])}** in `{sink['file']}` (`{sink['function']}`), "
                     f"reachable from `{sink['entryFile']}`: " + " -> ".join(f"`{c}`" for c in sink["chain"]))
        if reach.get("unresolvedEdges"):
            L.append(f"\n_{reach['unresolvedEdges']} call edge(s) unresolved (computed/dynamic dispatch "
                     "or unresolved imports); reachability is a lower bound._")
        L.append("")

    dyn = a.get("dynamicVerification") or {}
    if dyn:
        L.append("## Dynamic verification\n")
        L.append(f"Status: **{dyn.get('status', 'not-run')}**. {dyn.get('policy', '')}\n")
        for task in dyn.get("tasks", []):
            refs = task.get("triggeredBy", [])
            suffix = f" · requested by {len(refs)} finding(s)" if refs else ""
            L.append(f"- `{task['id']}` ({task['method']}): {task['status']}; "
                     f"approval required: {task['approvalRequired']}{suffix}")
        L.append("")

    L.append("## Findings\n")
    if not a["findings"]:
        L.append("_No malicious-code findings from the mcd lens. Read the coverage section: "
                 "absence of a finding is not a guarantee of safety._\n")
    for f in _ordered_findings(a):
        comp = f" · {f['composition']}" if f.get("composition") else ""
        L.append(f"### {_sev_tag(f['severity'])} {f['title']}  (mcd{comp})")
        L.append(f"Confidence: **{f['confidence']} ({f.get('confidenceLabel', '')})** · "
                 f"severity and confidence are independent.\n")
        L.append(f"{f['claim']}\n")
        if f.get("attenuators"):
            L.append("**Why confidence is limited:**")
            L += [f"- {x}" for x in f["attenuators"]]
            L.append("")
        if f.get("review"):
            L += _review_md(f["review"])
        evidence_rows, evidence_omitted = _deduped_evidence(f, idx)
        if evidence_rows:
            L.append("**Evidence:**")
            for oid, o, loc, ev in evidence_rows:
                line = f":{loc.get('startLine')}" if loc.get("startLine") else ""
                L.append(f"- `{o['atom']}` {loc.get('path', '')}{line}: "
                         f"{ev.get('summary', '')} ({oid})")
            if evidence_omitted:
                L.append(f"- _{evidence_omitted} duplicate evidence item(s) omitted._")
        L.append("\n**What would disprove this:**")
        L += [f"- {d}" for d in f.get("disproofCriteria", [])]
        if f.get("verification"):
            L.append("\n**Next verification:**")
            for v in f["verification"]:
                reason = f": {v['reason']}" if v.get("reason") else ""
                L.append(f"- [{v['method']}] {v['question']}{reason}")
        r = f.get("response") or {}
        if r:
            tier = f"tier {r['tier']} · " if "tier" in r else ""
            L.append(f"\n**Response:** {tier}{r.get('summary', '')}")
            for act in r.get("actions", []):
                L.append(f"  - {act}")
        L.append("")

    bins = a.get("binaries") or []
    L.append("## Binary artifacts\n")
    if bins:
        L.append(f"{s['binaryArtifacts']} artifact(s) triaged "
                 "(hash + strings + structure/import metadata, never executed); "
                 f"{s['binaryArtifactsWithHits']} with content-rule hits. "
                 "Decompiler provider status is recorded; no decompiler ran.\n")
        L.append("| path | format | depth | decompilation | drift | entropy | packer/archive | sha256 | bytes | string hits |")
        L.append("|---|---|---|---|---|---|---|---|---|---|")
        for b in bins[:50]:
            if b.get("error"):
                L.append(f"| {b['path']} | unreadable ({b['error']}) | - | - | - | - | - | - | - | - |")
            else:
                tag = b.get("packer") or (f"archive({b.get('members', 0)})" if b.get("archive") else "")
                depth = (b.get("analysisDepth") or {}).get("status", "")
                dec = (b.get("decompilation") or {}).get("status", "")
                drift = ", ".join((b.get("sourceDrift") or {}).get("indicators", [])[:3])
                L.append(f"| {b['path']} | {b.get('format', '')} | {depth} | {dec} | {drift} | "
                         f"{b.get('entropy', '')} | {tag} | "
                         f"{(b.get('sha256') or '')[:16]}... | {b.get('bytes', '')} | "
                         f"{b.get('stringObservations', 0)} |")
        if len(bins) > 50:
            L.append(f"\n_(+{len(bins) - 50} more binary artifacts)_")
    else:
        L.append("_No compiled or binary artifacts detected in scope._")
    L.append("")

    entries = _reading_entries(a["findings"])
    if entries:
        L.append("## How to read these findings\n")
        L.append(_READING_AXES + "\n")
        for code, title, guide in entries:
            L.append(f"**{code}:** {title}. {guide}\n")

    cov = a["coverage"]
    L.append("## Coverage (honest)\n")
    L.append(f"- Lenses run: {', '.join(cov.get('lensesRun', [])) or 'none'} · "
             f"observations: {cov.get('observationCount', 0)}")
    for n in cov.get("notes", []):
        L.append(f"- {n}")
    L.append("")
    L.append("## Contract\n")
    L.append(a["contract"]["note"])
    return "\n".join(L) + "\n"


# --------------------------------------------------------------------------
# HTML rendering (self-contained: inline CSS, no external assets, no framework).
# A single shareable per-project artifact, distinct from the corpus dashboard.
# --------------------------------------------------------------------------
_HTML_CSS = """
:root{--bg:#f6f7f9;--panel:#fff;--line:#d8dee8;--fg:#17202a;--mut:#637083;
--soft:#eef3f8;--crit:#b4233a;--high:#b54708;--med:#8a6f00;--low:#067647;
--info:#475467;--accent:#1f7a8c;}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.6 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:1060px;margin:0 auto;padding:32px 24px}
h1{font-size:26px;line-height:1.2;margin:0 0 4px}h2{font-size:17px;margin:28px 0 10px}
.sub{color:var(--mut);margin:0 0 6px}
.cards{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:14px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px 14px;min-width:0}
.card .n{font-size:22px;font-weight:700}.card .l{color:var(--mut);font-size:12px}
.takeaways{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin:12px 0 18px}
.take,.panel{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px 16px;margin:12px 0}
.take{margin:0}.take h3{font-size:14px;margin:0 0 6px}.take p{margin:0;color:var(--mut)}
.row{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:6px}
.lbl{color:var(--mut);font-size:12px;text-transform:uppercase;margin-top:10px;font-weight:700}
ul{margin:6px 0 0;padding-left:20px}li{margin:2px 0}
.chip{display:inline-block;padding:1px 8px;border-radius:6px;font-size:12px;font-weight:700}
.s-critical{background:#fce7ec;color:var(--crit)}
.s-high{background:#fff0dc;color:var(--high)}
.s-medium{background:#fff7c2;color:var(--med)}
.s-low{background:#dcfae6;color:var(--low)}
.s-informational,.s-none{background:#eef2f6;color:var(--info)}
.conf{color:var(--mut);font-variant-numeric:tabular-nums;font-size:13px}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
.note{color:var(--mut);font-size:13px;margin:6px 0}
.warn{background:#fff7e6;border:1px solid #f7c46c;color:var(--high);
border-radius:8px;padding:10px 14px;margin:12px 0;font-size:13px}
.disp{border-radius:8px;padding:18px 20px;margin:16px 0;border:1px solid var(--line)}
.disp-rec{font-size:21px;font-weight:800}
.disp-rat{opacity:.92;margin-top:6px;font-size:13px}
.d-quarantine{background:#fce7ec;border-color:#f2a2b5}
.d-quarantine .disp-rec{color:var(--crit)}
.d-review{background:#fff8d6;border-color:#eadb7a}
.d-review .disp-rec{color:var(--med)}
.d-clear{background:#e8f8ef;border-color:#a7e3bf}
.d-clear .disp-rec{color:var(--low)}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:8px;overflow:hidden;margin:8px 0}
th,td{text-align:left;padding:8px 12px;border-bottom:1px solid var(--line)}
th{color:var(--mut);font-weight:700;font-size:12px;text-transform:uppercase}
tr:last-child td{border-bottom:none}
footer{color:var(--mut);font-size:12px;margin-top:30px;border-top:1px solid var(--line);padding-top:14px}
.rev{border-left:3px solid var(--line);padding:2px 0 2px 12px;margin:10px 0}
.rev-escalate{border-color:var(--high)}.rev-refute,.rev-suppress{border-color:var(--low)}
.rev-deescalate{border-color:var(--med)}.rev-confirm{border-color:var(--mut)}
.dec{font-weight:700;font-size:12px;text-transform:uppercase}
.rev pre{background:#f2f4f7;border:1px solid var(--line);border-radius:6px;padding:8px 10px;overflow:auto;margin:6px 0;font-size:12px}
@media(max-width:760px){.wrap{padding:22px 14px}.cards,.takeaways{grid-template-columns:1fr}table{display:block;overflow-x:auto}}
"""

_DISP_CLASS = {"quarantine": "d-quarantine", "review": "d-review", "clear": "d-clear"}
_ACTION_COPY = {
    "quarantine": (
        "Hold before use",
        "Do not install, execute, ship, or train on this artifact until the verification and disproof questions are answered.",
    ),
    "review": (
        "Review before trusting",
        "There is enough signal to inspect, but the proof is incomplete or ambiguous. Work the evidence and disproof list first.",
    ),
    "clear": (
        "No MCD findings",
        "Parallax did not find malicious-code shapes in this scope. This is useful, but it is not a guarantee of safety.",
    ),
}


def _h(x):
    return html.escape(str(x)) if x is not None else ""


def _sev_chip(sev):
    s = sev or "none"
    return f'<span class="chip s-{html.escape(s)}">{html.escape(s)}</span>'


def _effective_recommendation(a: dict) -> str:
    adj = a.get("adjudication") or {}
    rd = adj.get("reviewedDisposition") or {}
    if rd.get("recommendation"):
        return rd["recommendation"]
    return (a.get("disposition") or {}).get("recommendation") or "clear"


def _binary_string_only_count(a: dict) -> int:
    total = 0
    for finding in a.get("findings") or []:
        attenuators = finding.get("attenuators") or []
        if any("Binary-string-only evidence" in str(x) for x in attenuators):
            total += 1
    return total


def _proof_status(a: dict) -> str:
    if not (a.get("findings") or []):
        return (
            "Clear means this lens has no malicious-code findings to prove. "
            "Check coverage before treating the artifact as low risk."
        )
    binary_only = _binary_string_only_count(a)
    if binary_only:
        return (
            f"{binary_only} finding(s) rely only on strings extracted from binary or archive members. "
            "Treat those as review leads until source, decompiled code, or control flow confirms behavior."
        )
    return (
        "Each finding is a claim with evidence, confidence, verification, and disproof criteria. "
        "It is not a verdict until those questions are checked."
    )


def _next_step(a: dict) -> str:
    rec = _effective_recommendation(a)
    if rec == "quarantine":
        return "Start with high and critical findings, then resolve any correlated signals before running the artifact."
    if rec == "review":
        return "Open the finding panels, check the evidence locations, and answer the disproof criteria."
    if (a.get("binaries") or []):
        return "Skim coverage and binary artifacts so the clear result is understood in scope."
    return "Use the coverage notes to decide whether another lens or runtime check is needed."


def _review_html(rv: dict) -> list:
    d = rv.get("decision", "")
    dropped = " (dropped from the disposition)" if rv.get("excludedFromDisposition") else ""
    L = [f'<div class="rev rev-{_h(d)}">',
         f'<div class="dec">Reviewer: {_h(_decision_phrase(d))}</div>',
         f'<div class="note">confidence {rv.get("originalConfidence")} &rarr; '
         f'{rv.get("reviewedConfidence")}{dropped}</div>']
    if rv.get("responseTier") is not None:
        xcheck = "" if rv.get("tierAgrees", True) else f' &middot; engine tier {rv.get("engineTier")}'
        L.append(f'<div class="note">Response: <strong>tier {rv["responseTier"]} - '
                 f'{_h(rv.get("responseTierName", ""))}</strong>{xcheck}</div>')
    if rv.get("proximityToHarm"):
        L.append(f'<div class="note">Proximity to harm: {_h(rv["proximityToHarm"])}</div>')
    if rv.get("justification"):
        L.append(f'<p>{_h(rv["justification"])}</p>')
    for snip in rv.get("evidenceSnippets", []):
        loc = snip.get("path", "") + (f":{snip['startLine']}" if snip.get("startLine") else "")
        L.append(f'<div class="note mono">{_h(loc)}</div><pre class="mono">{_h(snip.get("code", ""))}</pre>')
    if rv.get("disproofChecked"):
        L.append('<div class="lbl">Disproof checked</div><ul>')
        L += [f"<li>{_h(x)}</li>" for x in rv["disproofChecked"]]
        L.append("</ul>")
    if rv.get("references"):
        L.append(f'<div class="note">References: {_h(", ".join(rv["references"]))}</div>')
    who = rv.get("reviewer") or {}
    bits = " ".join(x for x in [who.get("backend"), who.get("model"), who.get("role")] if x)
    if bits:
        L.append(f'<div class="note">reviewed by {_h(bits)}</div>')
    L.append("</div>")
    return L


def _review_leads_html(leads: list[dict]) -> list:
    if not leads:
        return []
    L = ["<h2>Review leads</h2>",
         '<p class="note">Evidence-backed reasons to review that are not counted as single-file MCD findings.</p>']
    for lead in leads:
        L.append('<div class="panel">')
        L.append(f'<div class="row">{_sev_chip(lead.get("severity"))} '
                 f'<strong>{_h(lead.get("title", ""))}</strong></div>')
        L.append(f'<p>{_h(lead.get("claim", ""))}</p>')
        if lead.get("evidence"):
            L.append('<div class="lbl">Evidence chains</div><ul>')
            for ev in lead["evidence"]:
                chain = " -> ".join(ev.get("chain") or [])
                L.append(f'<li><strong>{_h(", ".join(ev.get("sinkKinds", [])))}</strong> '
                         f'in <span class="mono">{_h(ev.get("file"))}</span> '
                         f'(<span class="mono">{_h(ev.get("function"))}</span>), from '
                         f'<span class="mono">{_h(ev.get("entryFile"))}</span>: '
                         f'<span class="mono">{_h(chain)}</span></li>')
            L.append("</ul>")
        if lead.get("verify"):
            L.append('<div class="lbl">Verify next</div><ul>')
            L += [f"<li>{_h(v)}</li>" for v in lead["verify"]]
            L.append("</ul>")
        if lead.get("disproof"):
            L.append('<div class="lbl">What would lower confidence</div><ul>')
            L += [f"<li>{_h(d)}</li>" for d in lead["disproof"]]
            L.append("</ul>")
        L.append("</div>")
    return L


def _adjudication_html(adj: dict) -> list:
    c = adj.get("counts", {})
    L = ["<h2>Adjudication (agentic review)</h2>",
         f'<p class="note">{_h(adj.get("note", ""))}</p>', '<div class="panel">']
    who = adj.get("reviewer") or {}
    bits = " ".join(x for x in [who.get("backend"), who.get("model"), who.get("role")] if x)
    if bits:
        L.append(f'<div class="note">Reviewer: {_h(bits)}</div>')
    parts = [f"{k} {c[k]}" for k in ("confirm", "escalate", "deescalate", "refute", "suppress",
                                     "unreviewed") if c.get(k)]
    L.append(f'<div class="row">{_h(" · ".join(parts) or "no findings reviewed")}</div>')
    rl = adj.get("responseLevel")
    if rl:
        L.append(f'<div class="row"><strong>Response level: tier {rl["tier"]} - {_h(rl["name"])}</strong> '
                 f'&middot; {_h(rl["summary"])}</div>')
    if adj.get("moved"):
        L.append('<div class="lbl">Findings the review moved</div><ul>')
        for m in adj["moved"]:
            L.append(f'<li><span class="mono">{_h(m["findingId"])}</span> {_h(m["decision"])}: '
                     f'{m["originalConfidence"]} &rarr; {m["reviewedConfidence"]}</li>')
        L.append("</ul>")
    L.append(f'<div class="note">{_h(adj.get("rule", ""))}</div>')
    L.append("</div>")
    return L


def _reviewed_executive_summary(a: dict):
    """Human-facing summary for an adjudicated assessment.

    The original engine executive summary is preserved in the JSON, but once a
    review overlay exists the rendered report should lead with the reviewed
    disposition. Otherwise the HTML/Markdown can correctly show CLEAR at the top
    and then immediately repeat a stale pre-review REVIEW/QUARANTINE summary.
    """
    adj = a.get("adjudication") or {}
    rd = adj.get("reviewedDisposition")
    if not rd:
        return None

    rec = (rd.get("recommendation") or "").upper()
    engine = (adj.get("engineDisposition") or "").upper()
    if adj.get("dispositionChanged") and engine:
        move = f"The reviewer changed the engine disposition from {engine} to {rec}."
    elif engine:
        move = f"The engine disposition {engine} held after review."
    else:
        move = f"The reviewed disposition is {rec}."

    c = adj.get("counts") or {}
    counts = [f"{c[k]} {k}" for k in ("confirm", "escalate", "deescalate", "refute", "suppress")
              if c.get(k)]
    count_text = ""
    if counts:
        count_text = " Review outcome: " + ", ".join(counts) + "."

    rl = adj.get("responseLevel") or {}
    response = ""
    if rl:
        response = f" Response level: tier {rl.get('tier')} - {rl.get('name')}."

    rationale = rd.get("rationale") or ""
    return f"Disposition after review: {rec}. {move}{count_text}{response} {rationale}".strip()


def render_html(a: dict) -> str:
    s = a["summary"]
    disp = a.get("disposition") or {}
    es = a.get("executiveSummary") or {}
    rec = disp.get("recommendation") or "clear"
    idx = {o["id"]: o for o in a.get("observations", [])}
    L = ['<!doctype html><html lang="en"><head><meta charset="utf-8">',
         '<meta name="viewport" content="width=device-width,initial-scale=1">',
         f"<title>Parallax MCD assessment: {_h(a['target'].get('path', ''))}</title>",
         f"<style>{_HTML_CSS}</style></head><body><div class='wrap'>"]
    L.append("<h1>Parallax MCD assessment</h1>")
    L.append(f'<p class="sub mono">{_h(a["target"].get("path", ""))}</p>')
    L.append(f'<p class="sub">Ecosystems: '
             f'{_h(", ".join(a["target"].get("ecosystems", [])) or "none detected")} &middot; '
             f'scan {_h(a["generatedFrom"].get("scanId", ""))} &middot; '
             f'{_h(a["assessment"].get("scanner", ""))} {_h(a["assessment"].get("scannerVersion", ""))}</p>')

    adj = a.get("adjudication")
    if adj and adj.get("reviewedDisposition"):
        rd = adj["reviewedDisposition"]
        rrec = rd.get("recommendation") or "clear"
        L.append(f'<div class="disp {_DISP_CLASS.get(rrec, "d-clear")}">')
        L.append(f'<div class="disp-rec">{_h(rrec.upper())} <span class="conf">after review</span></div>')
        if adj.get("dispositionChanged"):
            L.append(f'<div class="note">Engine disposition {_h((adj.get("engineDisposition") or "").upper())}; '
                     "a reviewer's adjudication changed it. Engine values are preserved on each finding.</div>")
        L.append(f'<div class="disp-rat">{_h(rd.get("rationale", ""))}</div>')
    else:
        L.append(f'<div class="disp {_DISP_CLASS.get(rec, "d-clear")}">')
        L.append(f'<div class="disp-rec">{_h(rec.upper())}</div>')
        L.append(f'<div class="disp-rat">{_h(disp.get("rationale", ""))}</div>')
    L.append("</div>")

    conf = s.get("highestConfidence")
    L.append('<div class="cards">')
    L.append(f'<div class="card"><div class="n">{s["findingCount"]}</div>'
             '<div class="l">mcd findings</div></div>')
    L.append(f'<div class="card"><div class="n">{_sev_chip(s["highestSeverity"])}</div>'
             '<div class="l">highest severity</div></div>')
    L.append(f'<div class="card"><div class="n">{conf if conf is not None else "n/a"}</div>'
             '<div class="l">highest confidence</div></div>')
    L.append(f'<div class="card"><div class="n">{s["binaryArtifacts"]}</div>'
             '<div class="l">binaries</div></div>')
    L.append("</div>")
    L.append('<p class="note">Severity (how bad if real) and confidence (how sure) are independent.</p>')

    effective_rec = _effective_recommendation(a)
    action_title, action_body = _ACTION_COPY.get(effective_rec, _ACTION_COPY["review"])
    L.append("<h2>What this means</h2>")
    L.append('<div class="takeaways">')
    L.append(f'<div class="take"><h3>Recommended action: {_h(action_title)}</h3>'
             f'<p>{_h(action_body)}</p></div>')
    L.append(f'<div class="take"><h3>Proof status</h3><p>{_h(_proof_status(a))}</p></div>')
    L.append(f'<div class="take"><h3>Where to start</h3><p>{_h(_next_step(a))}</p></div>')
    L.append("</div>")

    if s.get("relatedFindingCount"):
        if s["findingCount"] == 0:
            L.append(f'<p class="warn">The scan also surfaced {s["relatedFindingCount"]} finding(s) '
                     'under other lenses (not malicious-code shapes). 0 mcd findings is not a safety '
                     'verdict; review the other-lens findings for the full picture.</p>')
        else:
            L.append(f'<p class="note">Also {s["relatedFindingCount"]} finding(s) under other lenses '
                     '(not malicious-code shapes); review those for that view.</p>')

    reviewed_summary = _reviewed_executive_summary(a)
    summary_text = reviewed_summary or es.get("text")
    if summary_text:
        L.append("<h2>Executive summary</h2>")
        L.append(f'<div class="panel">{_h(summary_text)}')
        if reviewed_summary:
            L.append('<div class="note">summary reflects the adjudicated review; the original engine '
                     'summary is preserved in JSON</div>')
        elif es.get("author", "engine") != "engine":
            L.append(f'<div class="note">summary prose written by {_h(es["author"])}; the disposition '
                     'is deterministic, set by the engine, not the model</div>')
        L.append("</div>")

    L += _review_leads_html(a.get("reviewLeads") or [])

    if adj:
        L += _adjudication_html(adj)

    enr = a.get("enrichment") or []
    if enr:
        L.append("<h2>Enrichment</h2>")
        L.append('<p class="note">Lens-neutral contextual facts that adjust confidence, never '
                 'severity. The adjusted value shows as a finding\'s effective confidence.</p>')
        providers = a.get("enrichmentProviders") or []
        if providers:
            L.append('<div class="panel">')
            L.append('<div class="lbl">Provider availability</div>')
            for p in [p for p in providers if p.get("availability") == "active"]:
                observed = p.get("observedAt") or "scan timestamp unavailable"
                counts = ""
                if "manifestCount" in p or "lockfileCount" in p:
                    counts = f" &middot; manifests {p.get('manifestCount', 0)}, lockfiles {p.get('lockfileCount', 0)}"
                L.append(f'<p><span class="mono">{_h(p.get("id"))}</span> active '
                         f'&middot; observedAt <span class="mono">{_h(observed)}</span> '
                         f'&middot; ttl <span class="mono">{_h(p.get("ttl", ""))}</span>{counts}</p>')
            unavailable = [p for p in providers if p.get("availability") == "unavailable"]
            if unavailable:
                L.append('<p class="note">Unavailable offline providers: '
                         + ", ".join(f'<span class="mono">{_h(p.get("id"))}</span>' for p in unavailable)
                         + "</p>")
            L.append("</div>")
        L.append('<div class="panel">')
        for e in enr:
            provider = e.get("provider") or {}
            observed = e.get("observedAt") or "scan timestamp unavailable"
            comps = e.get("appliesToCompositions") or []
            comp_note = ""
            if comps:
                preview = ", ".join(comps[:8])
                more = f", +{len(comps) - 8} more" if len(comps) > 8 else ""
                comp_note = f'<br><span class="note">Applies to MCD: {_h(preview + more)}</span>'
            L.append(f'<p><strong>{_h(e["id"])}</strong> ({_h(e["effect"])}): {_h(e["fact"])}'
                     f'<br><span class="note">{_h(e["rationale"])}</span>'
                     f'<br><span class="note">Provider <span class="mono">{_h(provider.get("id", "unknown"))}</span> '
                     f'&middot; observedAt <span class="mono">{_h(observed)}</span> '
                     f'&middot; ttl <span class="mono">{_h(e.get("ttl", ""))}</span></span>'
                     f'{comp_note}</p>')
        L.append("</div>")

    cors = a.get("correlations") or []
    if cors:
        L.append("<h2>Correlated signals</h2>")
        L.append('<p class="note">Findings that share a file or indicator, read as one story. '
                 'Co-location is corroborating context, not proven dataflow.</p>')
        for c in cors:
            L.append('<div class="panel">')
            L.append(f'<div class="row">{_sev_chip(c["severity"])} <strong>{_h(c["narrative"])}</strong></div>')
            L.append(f'<div class="note">Findings: {_h(", ".join(c["memberFindingIds"]))} &middot; '
                     f'signals: {_h(", ".join(c["signalTypes"]))}'
                     + (" (cross-signal)" if c.get("crossSignal") else "") + "</div>")
            if c.get("sharedFiles"):
                L.append('<div class="note">Shared files: '
                         + ", ".join(f'<span class="mono">{_h(p)}</span>' for p in c["sharedFiles"]) + "</div>")
            if c.get("insights"):
                L.append('<div class="lbl">Why it compounds</div><ul>')
                L += [f"<li>{_h(t)}</li>" for t in c["insights"]]
                L.append("</ul>")
            L.append(f'<div class="note">{_h(c.get("corroboration", ""))}</div>')
            if c.get("disproof"):
                L.append('<div class="lbl">What would break the link</div><ul>')
                L += [f"<li>{_h(d)}</li>" for d in c["disproof"]]
                L.append("</ul>")
            L.append("</div>")

    reach = a.get("reachability") or {}
    xsinks = [s for s in reach.get("reachableSinks", []) if s.get("crossFile")]
    if xsinks:
        L.append("<h2>Cross-file reachability</h2>")
        L.append('<p class="note">MCD sinks reachable from a package entry point through the call '
                 "graph, including chains split across files that no single-file finding would show.</p>")
        L.append("<ul>")
        for sink in xsinks:
            chain = " &rarr; ".join(f'<span class="mono">{_h(c)}</span>' for c in sink["chain"])
            L.append(f"<li><strong>{_h(', '.join(sink['sinkKinds']))}</strong> in "
                     f'<span class="mono">{_h(sink["file"])}</span> ({_h(sink["function"])}), reachable from '
                     f'<span class="mono">{_h(sink["entryFile"])}</span>: {chain}</li>')
        L.append("</ul>")
        if reach.get("unresolvedEdges"):
            L.append(f'<p class="note">{reach["unresolvedEdges"]} call edge(s) unresolved '
                     "(computed/dynamic dispatch or unresolved imports); reachability is a lower bound.</p>")

    dyn = a.get("dynamicVerification") or {}
    if dyn:
        L.append("<h2>Dynamic verification</h2>")
        L.append(f'<p class="note">Status: <strong>{_h(dyn.get("status", "not-run"))}</strong>. '
                 f'{_h(dyn.get("policy", ""))}</p>')
        L.append("<ul>")
        for task in dyn.get("tasks", []):
            refs = task.get("triggeredBy", [])
            suffix = f" requested by {len(refs)} finding(s)" if refs else ""
            L.append(f'<li><span class="mono">{_h(task["id"])}</span> ({_h(task["method"])}): '
                     f'{_h(task["status"])}; approval required: {_h(task["approvalRequired"])}'
                     f'{_h(suffix)}</li>')
        L.append("</ul>")

    L.append("<h2>Findings</h2>")
    if not a["findings"]:
        L.append('<p class="note">No malicious-code findings from the mcd lens. Read the coverage '
                 'section: absence of a finding is not a guarantee of safety.</p>')
    for f in _ordered_findings(a):
        comp = f' <span class="mono">{_h(f.get("composition"))}</span>' if f.get("composition") else ""
        eff = f.get("effectiveConfidence")
        eff_note = ""
        if isinstance(eff, (int, float)) and eff != f.get("confidence"):
            eff_note = f' &middot; effective {_h(eff)}'
        L.append('<div class="panel">')
        L.append(f'<div class="row">{_sev_chip(f["severity"])} <strong>{_h(f["title"])}</strong>{comp} '
                 f'<span class="conf">confidence {_h(f.get("confidence"))} '
                 f'({_h(f.get("confidenceLabel", ""))}){eff_note}</span></div>')
        L.append(f'<p>{_h(f["claim"])}</p>')
        if f.get("attenuators"):
            L.append('<div class="lbl">Why confidence is limited</div><ul>')
            L += [f"<li>{_h(x)}</li>" for x in f["attenuators"]]
            L.append("</ul>")
        if f.get("review"):
            L += _review_html(f["review"])
        evidence_rows, evidence_omitted = _deduped_evidence(f, idx)
        if evidence_rows:
            L.append('<div class="lbl">Evidence</div><ul>')
            for _oid, o, loc, ev in evidence_rows:
                line = f":{loc.get('startLine')}" if loc.get("startLine") else ""
                L.append(f'<li><span class="mono">{_h(o["atom"])}</span> '
                         f'{_h(loc.get("path", ""))}{_h(line)}: {_h(ev.get("summary", ""))}</li>')
            L.append("</ul>")
            if evidence_omitted:
                L.append(f'<div class="note">{evidence_omitted} duplicate evidence item(s) omitted.</div>')
        if f.get("disproofCriteria"):
            L.append('<div class="lbl">What would disprove this</div><ul>')
            L += [f"<li>{_h(d)}</li>" for d in f["disproofCriteria"]]
            L.append("</ul>")
        if f.get("verification"):
            L.append('<div class="lbl">Verify next</div><ul>')
            for v in f["verification"]:
                L.append(f'<li>[{_h(v.get("method"))}] {_h(v.get("question"))}</li>')
            L.append("</ul>")
        r = f.get("response") or {}
        if r:
            tier = f"tier {r['tier']} &middot; " if "tier" in r else ""
            L.append(f'<div class="note">Response: {tier}{_h(r.get("summary", ""))}</div>')
        L.append("</div>")

    bins = a.get("binaries") or []
    if bins:
        L.append("<h2>Binary artifacts</h2>")
        L.append(f'<p class="note">{s["binaryArtifacts"]} triaged '
                 '(hash + strings + structure/import metadata, never executed); '
                 f'{s["binaryArtifactsWithHits"]} with content-rule hits. '
                 'Decompiler provider status is recorded; no decompiler ran.</p>')
        L.append("<table><tr><th>Path</th><th>Format</th><th>Depth</th><th>Decompilation</th>"
                 "<th>Drift</th><th>Entropy</th><th>Packer/Archive</th>"
                 "<th>SHA-256</th><th>Bytes</th><th>Hits</th></tr>")
        for b in bins[:100]:
            if b.get("error"):
                L.append(f"<tr><td class='mono'>{_h(b['path'])}</td><td>unreadable</td>"
                         "<td>-</td><td>-</td><td>-</td><td>-</td><td>-</td>"
                         "<td>-</td><td>-</td><td>-</td></tr>")
            else:
                tag = b.get("packer") or (f"archive({b.get('members', 0)})" if b.get("archive") else "")
                depth = (b.get("analysisDepth") or {}).get("status", "")
                dec = (b.get("decompilation") or {}).get("status", "")
                drift = ", ".join((b.get("sourceDrift") or {}).get("indicators", [])[:3])
                L.append(f"<tr><td class='mono'>{_h(b['path'])}</td><td>{_h(b.get('format', ''))}</td>"
                         f"<td>{_h(depth)}</td><td>{_h(dec)}</td><td>{_h(drift)}</td>"
                         f"<td>{_h(b.get('entropy', ''))}</td><td>{_h(tag)}</td>"
                         f"<td class='mono'>{_h((b.get('sha256') or '')[:16])}...</td>"
                         f"<td>{_h(b.get('bytes', ''))}</td>"
                         f"<td>{_h(b.get('stringObservations', 0))}</td></tr>")
        L.append("</table>")

    entries = _reading_entries(a["findings"])
    if entries:
        L.append("<h2>How to read these findings</h2>")
        L.append(f'<p class="note">{_h(_READING_AXES)}</p>')
        for code, title, guide in entries:
            L.append(f'<div class="lbl"><span class="mono">{_h(code)}</span> {_h(title)}</div>'
                     f'<p class="note">{_h(guide)}</p>')

    L.append("<h2>Coverage (honest)</h2>")
    cov = a["coverage"]
    L.append(f'<p class="note">Lenses run: {_h(", ".join(cov.get("lensesRun", [])) or "none")} &middot; '
             f'observations: {_h(cov.get("observationCount", 0))}</p>')
    if cov.get("notes"):
        L.append("<ul>")
        L += [f'<li class="note">{_h(n)}</li>' for n in cov["notes"]]
        L.append("</ul>")

    L.append(f'<footer>{_h(a["contract"]["note"])}</footer>')
    L.append("</div></body></html>")
    return "\n".join(L)

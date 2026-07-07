"""Render an assessment to JSON / Markdown / self-contained HTML.

A clean rebuild of the report contract (the old 920-line renderer was the sloppy
code being replaced): disposition banner, executive summary, findings grouped by
severity with claim / evidence / disproof / verify / response, correlations, and
the coverage contract. Severity and confidence are always shown as two axes.
"""

from __future__ import annotations

import html
import json

from unmask.scanner.assess.common import _rank

_DISPOSITION_BLURB = {
    "quarantine": "Hold the artifact; do not install or run it until the verification questions are answered.",
    "review": "Malicious-code findings are present but below the quarantine bar; have an engineer resolve them.",
    "clear": "No malicious-code findings under the implemented compositions. Not a full safety guarantee.",
    "unknown": "The scan could not produce a reading.",
}


def render_json(assessment: dict) -> str:
    return json.dumps(assessment, indent=2)


# --- markdown --------------------------------------------------------------

def _findings_by_severity(findings):
    order = ["critical", "high", "medium", "low", "informational"]
    buckets = {s: [] for s in order}
    for f in findings:
        buckets.get(f.get("severity") or "informational", buckets["informational"]).append(f)
    return [(s, buckets[s]) for s in order if buckets[s]]


def render_markdown(assessment: dict) -> str:
    disp = assessment.get("disposition") or {}
    rec = disp.get("recommendation", "unknown")
    summ = assessment.get("summary") or {}
    out: list[str] = []
    out.append(f"# Malicious-code assessment — {rec.upper()}")
    out.append("")
    out.append(_DISPOSITION_BLURB.get(rec, ""))
    out.append("")
    out.append(f"**Findings:** {summ.get('findingCount', 0)}  ·  "
               f"**Highest severity:** {summ.get('highestSeverity') or 'none'}  ·  "
               f"**Highest confidence:** {summ.get('highestConfidence') if summ.get('highestConfidence') is not None else 'n/a'}  "
               f"(severity and confidence are independent axes)")
    if summ.get("compositions"):
        out.append(f"**Compositions:** {', '.join(summ['compositions'])}")
    out.append("")
    out.append("## Executive summary")
    out.append("")
    out.append((assessment.get("executiveSummary") or {}).get("text", ""))
    out.append("")

    for sev, group in _findings_by_severity(assessment.get("findings") or []):
        out.append(f"## {sev.capitalize()}")
        out.append("")
        for f in group:
            out.append(f"### {f.get('title')}  ·  {f.get('composition') or ''}")
            out.append(f"_severity {f.get('severity')} · confidence {f.get('confidence')} "
                       f"({f.get('confidenceLabel')})_")
            out.append("")
            out.append(f.get("claim", ""))
            if f.get("disproofCriteria"):
                out.append("\n**What would disprove this:**")
                out += [f"- {d}" for d in f["disproofCriteria"]]
            if f.get("verification"):
                out.append("\n**Verify next:**")
                out += [f"- {v.get('question')} _({v.get('method')})_" for v in f["verification"]]
            resp = f.get("response") or {}
            if resp:
                out.append(f"\n**Response (tier {resp.get('tier')}):** {resp.get('summary')}")
            out.append("")

    corrs = assessment.get("correlations") or []
    if corrs:
        out.append("## Correlations")
        out.append("")
        for c in corrs:
            out.append(f"- {c.get('narrative')}")
        out.append("")

    cov = assessment.get("coverage") or {}
    out.append("## Coverage")
    out.append("")
    out += [f"- {n}" for n in cov.get("notes", [])]
    out.append("")
    out.append("---")
    out.append(f"_{(assessment.get('contract') or {}).get('note', '')}_")
    out.append("")
    return "\n".join(out)


# --- html (self-contained) -------------------------------------------------

_CSS = """
:root{--bg:#0f1115;--fg:#e6e6e6;--muted:#9aa4b2;--card:#171a21;--line:#2a2f3a;
--crit:#ff5c5c;--high:#ff9d3c;--med:#ffd23c;--low:#7bd88f;--q:#ff5c5c;--r:#ffd23c;--c:#7bd88f}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 -apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif}
.wrap{max-width:860px;margin:0 auto;padding:32px 20px}
.banner{padding:16px 20px;border-radius:10px;font-weight:700;font-size:20px;margin-bottom:6px}
.q{background:rgba(255,92,92,.15);border:1px solid var(--q);color:var(--q)}
.r{background:rgba(255,210,60,.12);border:1px solid var(--r);color:var(--r)}
.c{background:rgba(123,216,143,.12);border:1px solid var(--c);color:var(--c)}
.muted{color:var(--muted)}.kv{margin:10px 0 24px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin:12px 0}
.sev{display:inline-block;font-size:12px;font-weight:700;padding:2px 8px;border-radius:6px;margin-right:8px}
.sev.critical{background:rgba(255,92,92,.2);color:var(--crit)}
.sev.high{background:rgba(255,157,60,.2);color:var(--high)}
.sev.medium{background:rgba(255,210,60,.2);color:var(--med)}
.sev.low{background:rgba(123,216,143,.2);color:var(--low)}
h1{font-size:22px}h2{border-bottom:1px solid var(--line);padding-bottom:6px;margin-top:32px}
h3{margin:4px 0}ul{margin:6px 0}code{background:#0b0d11;padding:1px 5px;border-radius:4px}
.foot{color:var(--muted);font-size:13px;margin-top:32px;border-top:1px solid var(--line);padding-top:16px}
"""


def _esc(s) -> str:
    return html.escape(str(s or ""))


def render_html(assessment: dict) -> str:
    disp = assessment.get("disposition") or {}
    rec = disp.get("recommendation", "unknown")
    cls = {"quarantine": "q", "review": "r", "clear": "c"}.get(rec, "r")
    summ = assessment.get("summary") or {}
    p: list[str] = ["<!doctype html><html><head><meta charset='utf-8'>",
                    "<meta name='viewport' content='width=device-width,initial-scale=1'>",
                    f"<title>MCD assessment — {rec}</title><style>{_CSS}</style></head><body><div class='wrap'>"]
    p.append(f"<div class='banner {cls}'>Disposition: {rec.upper()}</div>")
    p.append(f"<div class='muted'>{_esc(_DISPOSITION_BLURB.get(rec, ''))}</div>")
    p.append(f"<div class='kv'>Findings: <b>{summ.get('findingCount', 0)}</b> · "
             f"highest severity <b>{_esc(summ.get('highestSeverity') or 'none')}</b> · "
             f"highest confidence <b>{summ.get('highestConfidence') if summ.get('highestConfidence') is not None else 'n/a'}</b> "
             f"<span class='muted'>(two independent axes)</span></div>")
    p.append(f"<h2>Executive summary</h2><p>{_esc((assessment.get('executiveSummary') or {}).get('text', ''))}</p>")

    for sev, group in _findings_by_severity(assessment.get("findings") or []):
        for f in group:
            p.append("<div class='card'>")
            p.append(f"<h3><span class='sev {sev}'>{sev}</span>{_esc(f.get('title'))} "
                     f"<span class='muted'>{_esc(f.get('composition') or '')} · conf {f.get('confidence')}</span></h3>")
            p.append(f"<p>{_esc(f.get('claim'))}</p>")
            if f.get("disproofCriteria"):
                p.append("<p class='muted'>What would disprove this:</p><ul>"
                         + "".join(f"<li>{_esc(d)}</li>" for d in f["disproofCriteria"]) + "</ul>")
            if f.get("verification"):
                p.append("<p class='muted'>Verify next:</p><ul>"
                         + "".join(f"<li>{_esc(v.get('question'))} <span class='muted'>({_esc(v.get('method'))})</span></li>"
                                   for v in f["verification"]) + "</ul>")
            p.append("</div>")

    corrs = assessment.get("correlations") or []
    if corrs:
        p.append("<h2>Correlations</h2><ul>"
                 + "".join(f"<li>{_esc(c.get('narrative'))}</li>" for c in corrs) + "</ul>")

    cov = assessment.get("coverage") or {}
    p.append("<h2>Coverage</h2><ul>" + "".join(f"<li>{_esc(n)}</li>" for n in cov.get("notes", [])) + "</ul>")
    p.append(f"<div class='foot'>{_esc((assessment.get('contract') or {}).get('note', ''))}</div>")
    p.append("</div></body></html>")
    return "".join(p)

"""Render an assessment to JSON / Markdown / self-contained HTML.

A clean rebuild of the report contract (the old 920-line renderer was the sloppy
code being replaced): disposition banner, executive summary, findings grouped by
severity with claim / evidence / disproof / verify / response, correlations, and
the coverage contract. Severity and confidence are always shown as two axes.

The HTML output is fully self-contained: inline CSS only, no external
stylesheets/fonts/CDN/scripts, and every user- or finding-derived string is
HTML-escaped because an assessment can carry attacker-controlled evidence text.
"""

from __future__ import annotations

import html
import json

_DISPOSITION_BLURB = {
    "quarantine": "Hold the artifact; do not install or run it until the verification questions are answered.",
    "review": "Malicious-code findings are present but below the quarantine bar; have an engineer resolve them.",
    "clear": "No malicious-code findings under the implemented compositions. Not a full safety guarantee.",
    "unknown": "The scan could not produce a reading.",
}


def render_json(assessment: dict) -> str:
    return json.dumps(assessment, indent=2)


# --- shared helpers --------------------------------------------------------

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]


def _findings_by_severity(findings):
    buckets = {s: [] for s in _SEVERITY_ORDER}
    for f in findings:
        buckets.get(f.get("severity") or "informational", buckets["informational"]).append(f)
    return [(s, buckets[s]) for s in _SEVERITY_ORDER if buckets[s]]


def _confidence_pct(conf) -> str:
    if not isinstance(conf, (int, float)):
        return "n/a"
    return f"{round(conf * 100)}%"


# --- markdown --------------------------------------------------------------

def render_markdown(assessment: dict) -> str:
    disp = assessment.get("disposition") or {}
    rec = disp.get("recommendation", "unknown")
    summ = assessment.get("summary") or {}
    obs_by_id = {o.get("id"): o for o in (assessment.get("observations") or []) if o.get("id")}
    out: list[str] = []
    out.append(f"# Malicious-code assessment — {rec.upper()}")
    out.append("")
    out.append(_DISPOSITION_BLURB.get(rec, ""))
    out.append("")
    if disp.get("rationale"):
        out.append(f"> {disp['rationale']}")
        out.append("")
    out.append(f"**Findings:** {summ.get('findingCount', 0)}  ·  "
               f"**Highest severity:** {summ.get('highestSeverity') or 'none'}  ·  "
               f"**Highest confidence:** "
               f"{summ.get('highestConfidence') if summ.get('highestConfidence') is not None else 'n/a'}"
               f"{f' ({summ.get('highestConfidenceLabel')})' if summ.get('highestConfidenceLabel') else ''}  "
               f"(severity and confidence are independent axes)")
    if summ.get("compositions"):
        out.append(f"**Compositions:** {', '.join(summ['compositions'])}")
    out.append("")
    out.append("## Executive summary")
    out.append("")
    out.append((assessment.get("executiveSummary") or {}).get("text", ""))
    out.append("")

    for sev, group in _findings_by_severity(assessment.get("findings") or []):
        out.append(f"## {sev.capitalize()} severity")
        out.append("")
        for f in group:
            out.append(f"### {f.get('title')}  ·  {f.get('composition') or ''}")
            out.append(f"_Severity: **{f.get('severity')}** · Confidence: **{f.get('confidence')}** "
                       f"({f.get('confidenceLabel')})_  — two independent axes")
            out.append("")
            out.append(f.get("claim", ""))
            if f.get("disproofCriteria"):
                out.append("\n**What would disprove this:**")
                out += [f"- {d}" for d in f["disproofCriteria"]]
            if f.get("verification"):
                out.append("\n**Verify next:**")
                for v in f["verification"]:
                    line = f"- {v.get('question')} _({v.get('method')})_"
                    if v.get("reason"):
                        line += f" — {v['reason']}"
                    out.append(line)
            resp = f.get("response") or {}
            if resp:
                out.append(f"\n**Response (tier {resp.get('tier')}):** {resp.get('summary')}")
                out += [f"  - {a}" for a in resp.get("actions", [])]
            ev = [obs_by_id[oid] for oid in (f.get("evidence") or []) if oid in obs_by_id]
            if ev:
                out.append("\n**Evidence:**")
                for o in ev:
                    loc = o.get("location") or {}
                    where = loc.get("path") or "?"
                    if loc.get("line"):
                        where += f":{loc['line']}"
                    matched = (o.get("evidence") or {}).get("matchedText")
                    line = f"- `{where}` — {(o.get('evidence') or {}).get('summary', '')}"
                    if matched:
                        line += f"  →  `{matched}`"
                    out.append(line)
            out.append("")

    corrs = assessment.get("correlations") or []
    if corrs:
        out.append("## Correlations")
        out.append("")
        for c in corrs:
            out.append(f"- {c.get('narrative')}")
        out.append("")

    adj = assessment.get("adjudication")
    if adj:
        rd = adj.get("reviewedDisposition") or {}
        out.append("## Agentic review")
        out.append("")
        line = f"**Reviewed disposition:** {rd.get('recommendation', '?').upper()}"
        if adj.get("dispositionChanged") and adj.get("engineDisposition"):
            line += f" (engine: {adj['engineDisposition'].upper()})"
        out.append(line)
        if rd.get("rationale"):
            out += ["", rd["rationale"]]
        out.append("")
        for r in adj.get("reviews", []):
            out.append(f"- **{r.get('finding_id')}** — {r.get('verdict')} "
                       f"(conf {r.get('reviewed_confidence')}): {r.get('justification')}")
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
:root{
  --bg:#0e1116; --panel:#161b22; --panel-2:#1b212b; --fg:#e7ecf3; --muted:#9aa6b6;
  --faint:#6b7787; --line:#2a323d; --line-soft:#232a34; --accent:#6ea8fe;
  --crit:#ff6b6b; --high:#ff9f45; --med:#ffd23c; --low:#63c98a; --info:#7aa2c4;
  --q:#ff6b6b; --qbg:#2a1516; --r:#ffc94d; --rbg:#2a230f; --c:#63c98a; --cbg:#132318;
  --code-bg:#0a0d12; --shadow:0 1px 2px rgba(0,0,0,.4),0 8px 24px rgba(0,0,0,.28);
  --radius:12px;
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{
  margin:0; background:var(--bg); color:var(--fg);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,
    "Apple Color Emoji","Segoe UI Emoji",sans-serif;
  font-size:16px; line-height:1.6; -webkit-font-smoothing:antialiased;
}
.wrap{max-width:880px; margin:0 auto; padding:40px 22px 72px}
a{color:var(--accent)}
:focus-visible{outline:2px solid var(--accent); outline-offset:2px; border-radius:4px}

/* Masthead */
.masthead{display:flex; align-items:baseline; justify-content:space-between;
  gap:12px; flex-wrap:wrap; margin-bottom:22px}
.masthead .kicker{font-size:12px; font-weight:700; letter-spacing:.14em;
  text-transform:uppercase; color:var(--faint)}
.masthead .target{font-size:13px; color:var(--muted); word-break:break-all;
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}

/* Disposition banner */
.banner{border:1px solid var(--line); border-radius:var(--radius);
  padding:20px 22px; box-shadow:var(--shadow); border-left-width:6px}
.banner.q{background:var(--qbg); border-color:var(--q)}
.banner.r{background:var(--rbg); border-color:var(--r)}
.banner.c{background:var(--cbg); border-color:var(--c)}
.banner .verdict{display:flex; align-items:center; gap:12px; flex-wrap:wrap}
.banner .dot{width:14px; height:14px; border-radius:50%; flex:0 0 auto}
.banner.q .dot{background:var(--q)} .banner.r .dot{background:var(--r)} .banner.c .dot{background:var(--c)}
.banner h1{margin:0; font-size:26px; font-weight:800; letter-spacing:.01em; line-height:1.2}
.banner.q h1{color:var(--q)} .banner.r h1{color:var(--r)} .banner.c h1{color:var(--c)}
.banner .blurb{margin:10px 0 0; color:var(--fg); font-size:15px}
.banner .rationale{margin:12px 0 0; color:var(--muted); font-size:14px; line-height:1.55}
.banner .drivers{margin:12px 0 0; padding:0; list-style:none;
  display:flex; flex-direction:column; gap:6px}
.banner .drivers li{position:relative; padding-left:20px; font-size:14px; color:var(--fg)}
.banner .drivers li::before{content:"→"; position:absolute; left:0; color:var(--faint)}

/* Axes summary strip */
.axes{display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
  gap:12px; margin:22px 0 8px}
.axis{background:var(--panel); border:1px solid var(--line-soft); border-radius:10px;
  padding:13px 15px}
.axis .lbl{font-size:11px; font-weight:700; letter-spacing:.08em; text-transform:uppercase;
  color:var(--faint); margin-bottom:4px}
.axis .val{font-size:20px; font-weight:800; line-height:1.1}
.axis .sub{font-size:12px; color:var(--muted); margin-top:3px}
.axes-note{font-size:12.5px; color:var(--faint); margin:2px 2px 0}

/* Section headers */
h2.sec{font-size:15px; font-weight:700; letter-spacing:.02em; text-transform:uppercase;
  color:var(--muted); margin:40px 0 4px; padding-bottom:8px;
  border-bottom:1px solid var(--line-soft)}
h2.sec .count{color:var(--faint); font-weight:600; text-transform:none; letter-spacing:0}
.exec{background:var(--panel); border:1px solid var(--line-soft); border-radius:10px;
  padding:16px 18px; margin-top:14px; font-size:15px; color:var(--fg)}

/* Severity group heading */
.sevgroup{margin-top:26px}
.sevgroup > .sevhead{display:flex; align-items:center; gap:10px; margin:0 0 4px}
.sevgroup > .sevhead .bar{width:4px; height:18px; border-radius:2px}
.sevgroup > .sevhead .name{font-size:13px; font-weight:700; text-transform:uppercase;
  letter-spacing:.06em}
.sevgroup > .sevhead .n{font-size:12.5px; color:var(--faint)}
.bar.critical{background:var(--crit)} .name.critical{color:var(--crit)}
.bar.high{background:var(--high)} .name.high{color:var(--high)}
.bar.medium{background:var(--med)} .name.medium{color:var(--med)}
.bar.low{background:var(--low)} .name.low{color:var(--low)}
.bar.informational{background:var(--info)} .name.informational{color:var(--info)}

/* Finding card */
.card{background:var(--panel); border:1px solid var(--line); border-radius:var(--radius);
  padding:18px 20px; margin:12px 0; box-shadow:var(--shadow)}
.card .top{display:flex; align-items:flex-start; justify-content:space-between;
  gap:14px; flex-wrap:wrap}
.card h3{margin:0; font-size:18px; font-weight:700; line-height:1.35; flex:1 1 260px}
.chips{display:flex; gap:7px; flex-wrap:wrap; align-items:center}
.chip{display:inline-flex; align-items:center; gap:5px; font-size:11.5px; font-weight:700;
  padding:3px 9px; border-radius:999px; white-space:nowrap; border:1px solid transparent}
.chip .k{font-weight:600; opacity:.72; letter-spacing:.02em}
.chip.sev-critical{background:rgba(255,107,107,.14); color:var(--crit); border-color:rgba(255,107,107,.4)}
.chip.sev-high{background:rgba(255,159,69,.14); color:var(--high); border-color:rgba(255,159,69,.4)}
.chip.sev-medium{background:rgba(255,210,60,.14); color:var(--med); border-color:rgba(255,210,60,.4)}
.chip.sev-low{background:rgba(99,201,138,.14); color:var(--low); border-color:rgba(99,201,138,.4)}
.chip.sev-informational{background:rgba(122,162,196,.14); color:var(--info); border-color:rgba(122,162,196,.4)}
.chip.conf{background:var(--panel-2); color:var(--fg); border-color:var(--line)}
.chip.comp{background:var(--panel-2); color:var(--muted); border-color:var(--line);
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:11px}
.card .claim{margin:12px 0 0; font-size:15.5px; color:var(--fg)}

/* Confidence meter */
.meter{display:inline-flex; align-items:center; gap:6px}
.meter .track{width:44px; height:6px; border-radius:3px; background:var(--line); overflow:hidden}
.meter .fill{height:100%; background:var(--accent); border-radius:3px}

/* Finding detail blocks */
.block{margin-top:16px}
.block > .h{font-size:11px; font-weight:700; letter-spacing:.09em; text-transform:uppercase;
  color:var(--faint); margin-bottom:7px}
.block ul{margin:0; padding-left:0; list-style:none; display:flex; flex-direction:column; gap:6px}
.block ul.disproof li,.block ul.verify li{position:relative; padding-left:22px; font-size:14.5px}
.block ul.disproof li::before{content:"✕"; position:absolute; left:0; color:var(--faint); font-size:12px; top:2px}
.block ul.verify li::before{content:"?"; position:absolute; left:2px; color:var(--accent); font-weight:800; top:0}
.block ul.verify .method{display:inline-block; font-size:11px; font-weight:700; color:var(--muted);
  background:var(--panel-2); border:1px solid var(--line); border-radius:5px; padding:0 6px;
  margin-left:6px; font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; text-transform:lowercase}
.block ul.verify .reason{display:block; color:var(--muted); font-size:13px; margin-top:2px}

/* Response */
.response{margin-top:16px; background:var(--panel-2); border:1px solid var(--line-soft);
  border-radius:10px; padding:12px 14px}
.response .rh{font-size:11px; font-weight:700; letter-spacing:.09em; text-transform:uppercase;
  color:var(--faint); display:flex; align-items:center; gap:8px; margin-bottom:6px}
.response .tier{font-size:11px; font-weight:700; color:var(--accent);
  border:1px solid rgba(110,168,254,.4); background:rgba(110,168,254,.1); border-radius:5px; padding:1px 7px}
.response .summary{font-size:14.5px}
.response ul{margin:8px 0 0; padding-left:0; list-style:none; display:flex; flex-direction:column; gap:5px}
.response li{position:relative; padding-left:18px; font-size:14px; color:var(--muted)}
.response li::before{content:""; position:absolute; left:2px; top:9px; width:6px; height:6px;
  border-radius:50%; background:var(--faint)}

/* Evidence */
.evidence{margin-top:16px; display:flex; flex-direction:column; gap:8px}
.ev{border:1px solid var(--line-soft); border-radius:8px; overflow:hidden; background:var(--code-bg)}
.ev .evhead{display:flex; align-items:center; gap:8px; flex-wrap:wrap;
  padding:7px 11px; background:var(--panel-2); border-bottom:1px solid var(--line-soft)}
.ev .loc{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:12.5px;
  color:var(--fg); font-weight:600}
.ev .atom{font-size:10.5px; font-weight:700; color:var(--muted); letter-spacing:.04em;
  border:1px solid var(--line); border-radius:5px; padding:0 6px}
.ev .summ{font-size:13px; color:var(--muted); flex:1 1 100%; padding:2px 11px 0}
.ev pre{margin:0; padding:9px 11px; overflow-x:auto;
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:12.5px;
  color:#e6d7b8; line-height:1.5}

/* Correlations */
.corr{background:var(--panel); border:1px solid var(--line); border-left:4px solid var(--accent);
  border-radius:10px; padding:14px 16px; margin:12px 0; box-shadow:var(--shadow)}
.corr .narr{font-size:15px}
.corr .meta{margin-top:8px; display:flex; gap:6px; flex-wrap:wrap}
.corr .tag{font-size:11px; color:var(--muted); border:1px solid var(--line); border-radius:5px;
  padding:1px 7px; font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.corr .insights{margin:10px 0 0; padding-left:20px; color:var(--muted); font-size:13.5px}

/* Empty state */
.empty{background:var(--panel); border:1px dashed var(--line); border-radius:10px;
  padding:22px; text-align:center; color:var(--muted); margin-top:14px}

/* Coverage / footer */
.foot{margin-top:44px; padding-top:20px; border-top:1px solid var(--line-soft)}
.foot .covlist{margin:0; padding-left:0; list-style:none; display:flex; flex-direction:column; gap:9px}
.foot .covlist li{font-size:13px; color:var(--muted); line-height:1.55; padding-left:18px; position:relative}
.foot .covlist li::before{content:"•"; position:absolute; left:2px; color:var(--faint)}
.foot .contract{margin-top:18px; font-size:13px; color:var(--faint); line-height:1.6;
  border-left:3px solid var(--line); padding:2px 0 2px 14px}
.foot .contract strong{color:var(--muted)}

@media (max-width:560px){
  .wrap{padding:26px 15px 56px}
  .banner h1{font-size:22px}
  .card{padding:15px 16px}
  .card h3{flex-basis:100%}
}

@media print{
  :root{--bg:#fff; --panel:#fff; --panel-2:#f6f7f9; --fg:#14181d; --muted:#4a5460;
    --faint:#6b7787; --line:#c9d1da; --line-soft:#e2e7ec; --code-bg:#f6f7f9;
    --qbg:#fdeeee; --rbg:#fdf6e3; --cbg:#eef7f0; --shadow:none}
  body{font-size:11pt}
  .wrap{max-width:100%; padding:0}
  .card,.corr,.banner,.exec,.axis,.response,.ev{box-shadow:none;
    break-inside:avoid; page-break-inside:avoid}
  .ev pre{color:#5a4a1a; white-space:pre-wrap; word-break:break-word}
  h2.sec{break-after:avoid; page-break-after:avoid}
  a{color:inherit; text-decoration:none}
}
"""


def _esc(s) -> str:
    # Escape rigorously, but do not swallow meaningful falsy values (0, False):
    # only None renders as empty.
    return html.escape("" if s is None else str(s))


def _sev_meta(sev: str) -> tuple[str, str]:
    """Return (css-class-suffix, display-label) for a severity."""
    s = sev if sev in _SEVERITY_ORDER else "informational"
    return s, s.capitalize()


def _confidence_chip(conf, label) -> str:
    """Confidence axis chip with a small meter — deliberately distinct from severity."""
    pct = _confidence_pct(conf)
    lbl = _esc(label) if label else ""
    lbl_html = f" · {lbl}" if lbl else ""
    if isinstance(conf, (int, float)):
        width = max(0, min(100, round(conf * 100)))
        meter = (f"<span class='meter'><span class='track'>"
                 f"<span class='fill' style='width:{width}%'></span></span></span>")
    else:
        meter = ""
    return (f"<span class='chip conf'>{meter}<span class='k'>confidence</span> "
            f"{_esc(pct)}{lbl_html}</span>")


def _finding_card(f: dict, obs_by_id: dict) -> str:
    sev_cls, _ = _sev_meta(f.get("severity") or "informational")
    parts: list[str] = ["<article class='card'>"]

    # Header: title + the two independent axes as separate chips.
    chips = [f"<span class='chip sev-{sev_cls}'><span class='k'>severity</span> {_esc(sev_cls)}</span>",
             _confidence_chip(f.get("confidence"), f.get("confidenceLabel"))]
    if f.get("composition"):
        chips.append(f"<span class='chip comp'>{_esc(f.get('composition'))}</span>")
    parts.append("<div class='top'>")
    parts.append(f"<h3>{_esc(f.get('title'))}</h3>")
    parts.append("<div class='chips'>" + "".join(chips) + "</div>")
    parts.append("</div>")

    if f.get("claim"):
        parts.append(f"<p class='claim'>{_esc(f.get('claim'))}</p>")

    if f.get("disproofCriteria"):
        parts.append("<div class='block'><div class='h'>What would disprove this</div>"
                     "<ul class='disproof'>"
                     + "".join(f"<li>{_esc(d)}</li>" for d in f["disproofCriteria"])
                     + "</ul></div>")

    if f.get("verification"):
        items = []
        for v in f["verification"]:
            method = (f"<span class='method'>{_esc(v.get('method'))}</span>"
                      if v.get("method") else "")
            reason = (f"<span class='reason'>{_esc(v.get('reason'))}</span>"
                      if v.get("reason") else "")
            items.append(f"<li>{_esc(v.get('question'))}{method}{reason}</li>")
        parts.append("<div class='block'><div class='h'>Verify next</div>"
                     "<ul class='verify'>" + "".join(items) + "</ul></div>")

    resp = f.get("response") or {}
    if resp:
        tier = resp.get("tier")
        tier_html = f"<span class='tier'>Tier {_esc(tier)}</span>" if tier is not None else ""
        actions = "".join(f"<li>{_esc(a)}</li>" for a in resp.get("actions", []))
        actions_html = f"<ul>{actions}</ul>" if actions else ""
        parts.append("<div class='response'>"
                     f"<div class='rh'>Recommended response {tier_html}</div>"
                     f"<div class='summary'>{_esc(resp.get('summary'))}</div>"
                     f"{actions_html}</div>")

    # Cited evidence (file:line + matched text), where the observation is available.
    ev_obs = [obs_by_id[oid] for oid in (f.get("evidence") or []) if oid in obs_by_id]
    if ev_obs:
        rows = []
        for o in ev_obs:
            loc = o.get("location") or {}
            where = _esc(loc.get("path") or "(unlocated)")
            if loc.get("line"):
                where += f":{_esc(loc['line'])}"
            atom = (f"<span class='atom'>{_esc(o.get('atom'))}</span>"
                    if o.get("atom") else "")
            evd = o.get("evidence") or {}
            summ = (f"<div class='summ'>{_esc(evd.get('summary'))}</div>"
                    if evd.get("summary") else "")
            matched = evd.get("matchedText")
            pre = f"<pre>{_esc(matched)}</pre>" if matched else ""
            rows.append("<div class='ev'>"
                        f"<div class='evhead'><span class='loc'>{where}</span>{atom}{summ}</div>"
                        f"{pre}</div>")
        parts.append("<div class='block'><div class='h'>Evidence</div>"
                     "<div class='evidence'>" + "".join(rows) + "</div></div>")

    parts.append("</article>")
    return "".join(parts)


def _adjudication_html(adj: dict) -> str:
    """The agentic-review overlay: the reviewed disposition + per-finding verdicts,
    shown next to the engine disposition."""
    rd = adj.get("reviewedDisposition") or {}
    rec = rd.get("recommendation", "unknown")
    cls = {"quarantine": "q", "review": "r", "clear": "c"}.get(rec, "r")
    p = [f"<section class='banner {cls}' role='region' aria-label='Agentic review'>",
         "<div class='verdict'><span class='dot' aria-hidden='true'></span>"
         f"<h1 style='font-size:20px'>Reviewed: {_esc(rec).upper()}</h1></div>"]
    if adj.get("dispositionChanged") and adj.get("engineDisposition"):
        p.append(f"<p class='rationale'>Review changed the disposition from "
                 f"<strong>{_esc(adj['engineDisposition']).upper()}</strong> to "
                 f"<strong>{_esc(rec).upper()}</strong>.</p>")
    if rd.get("rationale"):
        p.append(f"<p class='rationale'>{_esc(rd['rationale'])}</p>")
    counts = adj.get("counts") or {}
    if counts:
        p.append("<div class='chips' style='margin-top:8px'>"
                 + "".join(f"<span class='chip'>{_esc(k)}: {_esc(v)}</span>" for k, v in counts.items())
                 + "</div>")
    reviews = adj.get("reviews") or []
    if reviews:
        p.append("<ul class='drivers'>" + "".join(
            f"<li><strong>{_esc(r.get('finding_id'))}</strong> — {_esc(r.get('verdict'))} "
            f"(conf {_esc(r.get('reviewed_confidence'))}): {_esc(r.get('justification'))}</li>"
            for r in reviews) + "</ul>")
    p.append("<p class='blurb'>The engine found the shapes; a reviewer read the evidence behind "
             "each. The reviewed disposition is recomputed by rule from the verdicts, not set by "
             "the model.</p></section>")
    return "".join(p)


def render_html(assessment: dict) -> str:
    disp = assessment.get("disposition") or {}
    rec = disp.get("recommendation", "unknown")
    cls = {"quarantine": "q", "review": "r", "clear": "c"}.get(rec, "r")
    summ = assessment.get("summary") or {}
    target = (assessment.get("target") or {}).get("path", "")
    obs_by_id = {o.get("id"): o for o in (assessment.get("observations") or []) if o.get("id")}

    p: list[str] = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        f"<title>MCD assessment — {_esc(rec)}</title>",
        f"<style>{_CSS}</style></head><body>",
        "<main class='wrap'>",
    ]

    # Masthead
    p.append("<div class='masthead'>"
             "<span class='kicker'>Malicious-code assessment</span>")
    if target:
        p.append(f"<span class='target'>{_esc(target)}</span>")
    p.append("</div>")

    # Disposition banner
    p.append(f"<section class='banner {cls}' role='region' aria-label='Disposition'>")
    p.append("<div class='verdict'><span class='dot' aria-hidden='true'></span>"
             f"<h1>{_esc(rec).upper()}</h1></div>")
    p.append(f"<p class='blurb'>{_esc(_DISPOSITION_BLURB.get(rec, ''))}</p>")
    if disp.get("rationale"):
        p.append(f"<p class='rationale'>{_esc(disp['rationale'])}</p>")
    if disp.get("drivers"):
        p.append("<ul class='drivers'>"
                 + "".join(f"<li>{_esc(d)}</li>" for d in disp["drivers"]) + "</ul>")
    p.append("</section>")

    # Agentic-review overlay (present only when the run was adjudicated)
    if assessment.get("adjudication"):
        p.append(_adjudication_html(assessment["adjudication"]))

    # Two-axis summary strip (severity and confidence kept visibly independent)
    hi_sev = summ.get("highestSeverity")
    hi_conf = summ.get("highestConfidence")
    hi_conf_lbl = summ.get("highestConfidenceLabel")
    conf_sub = _esc(hi_conf_lbl) + " confidence" if hi_conf_lbl else "no findings"
    p.append("<div class='axes'>")
    p.append("<div class='axis'><div class='lbl'>Findings</div>"
             f"<div class='val'>{_esc(summ.get('findingCount', 0))}</div>"
             "<div class='sub'>malicious-code shapes</div></div>")
    p.append("<div class='axis'><div class='lbl'>Highest severity</div>"
             f"<div class='val'>{_esc(hi_sev or 'none')}</div>"
             "<div class='sub'>how bad if real</div></div>")
    p.append("<div class='axis'><div class='lbl'>Highest confidence</div>"
             f"<div class='val'>{_esc(_confidence_pct(hi_conf))}</div>"
             f"<div class='sub'>{conf_sub} · how sure</div></div>")
    p.append("</div>")
    p.append("<p class='axes-note'>Severity (how bad if real) and confidence (how sure) "
             "are independent axes and are never blended into one score.</p>")
    if summ.get("compositions"):
        comps = " ".join(f"<span class='chip comp'>{_esc(c)}</span>" for c in summ["compositions"])
        p.append(f"<div class='axes' style='grid-template-columns:1fr'><div class='axis'>"
                 f"<div class='lbl'>Compositions matched</div>"
                 f"<div class='chips' style='margin-top:6px'>{comps}</div></div></div>")

    # Executive summary
    exec_text = (assessment.get("executiveSummary") or {}).get("text", "")
    if exec_text:
        p.append("<h2 class='sec'>Executive summary</h2>")
        p.append(f"<div class='exec'>{_esc(exec_text)}</div>")

    # Findings grouped by severity
    groups = _findings_by_severity(assessment.get("findings") or [])
    total = summ.get("findingCount", sum(len(g) for _, g in groups))
    p.append(f"<h2 class='sec'>Findings <span class='count'>({_esc(total)})</span></h2>")
    if groups:
        for sev, group in groups:
            sev_cls, sev_label = _sev_meta(sev)
            plural = "finding" if len(group) == 1 else "findings"
            p.append("<div class='sevgroup'><div class='sevhead'>"
                     f"<span class='bar {sev_cls}'></span>"
                     f"<span class='name {sev_cls}'>{_esc(sev_label)}</span>"
                     f"<span class='n'>· {len(group)} {plural}</span></div>")
            for f in group:
                p.append(_finding_card(f, obs_by_id))
            p.append("</div>")
    else:
        p.append("<div class='empty'>No malicious-code findings under the implemented "
                 "compositions.</div>")

    # Correlations
    corrs = assessment.get("correlations") or []
    if corrs:
        p.append(f"<h2 class='sec'>Correlations <span class='count'>({len(corrs)})</span></h2>")
        for c in corrs:
            p.append("<div class='corr'>")
            p.append(f"<div class='narr'>{_esc(c.get('narrative'))}</div>")
            tags = []
            if c.get("crossSignal"):
                tags.append("cross-signal")
            for st in c.get("signalTypes", []):
                tags.append(_esc(st))
            for sf in c.get("sharedFiles", []):
                tags.append(_esc(sf))
            if tags:
                p.append("<div class='meta'>"
                         + "".join(f"<span class='tag'>{t}</span>" for t in tags) + "</div>")
            if c.get("insights"):
                p.append("<ul class='insights'>"
                         + "".join(f"<li>{_esc(i)}</li>" for i in c["insights"]) + "</ul>")
            p.append("</div>")

    # Coverage + contract footer (clearly secondary)
    p.append("<footer class='foot'>")
    cov = assessment.get("coverage") or {}
    notes = cov.get("notes", [])
    if notes:
        p.append("<h2 class='sec'>Coverage</h2>")
        p.append("<ul class='covlist'>"
                 + "".join(f"<li>{_esc(n)}</li>" for n in notes) + "</ul>")
    contract_note = (assessment.get("contract") or {}).get("note", "")
    p.append("<p class='contract'><strong>This is a next-action recommendation, "
             "not a maliciousness verdict.</strong> "
             f"{_esc(contract_note)}</p>")
    p.append("</footer>")

    p.append("</main></body></html>")
    return "".join(p)

"""Native build_assessment: project native observations + findings into an MCD
assessment dict (disposition, summary, correlations, coverage).

Rebuilt clean over the native pipeline (no engine scan-report dependency).
Enrichment (contextual confidence adjustment via external providers) is offline in
core, so it is a no-op here plus a coverage note; the deterministic disposition,
severity/confidence separation, and correlation are preserved exactly.
"""

from __future__ import annotations

from pathlib import Path

from unmask.scanner.assess.common import (
    ASSESSMENT_VERSION, MCD_LENS, SCANNER, SCANNER_VERSION,
    _CONTRACT_NOTE, _IMPLEMENTATION_NOTE, _confidence_label, _max_confidence, _max_severity,
)
from unmask.scanner.assess.correlate import _correlate
from unmask.scanner.assess.disposition import _disposition, _exec_summary, _review_leads

_OFFLINE_ENRICHMENT_NOTE = (
    "Enrichment providers: local static analysis only; registry/OSINT/threat-intel "
    "providers are offline, so confidence reflects static evidence without external "
    "corroboration. Offline absence lowers certainty; it is not a clean bill of health."
)


_CONTEXT_LINES = 2          # code lines shown before/after the match (a 5-line window)
_MAX_LINE_CHARS = 220       # long (minified) lines are windowed around the match, not dumped whole


def _window_line(raw: str, col):
    """Keep a match-line legible when the source is minified (one huge line): window it
    to ~_MAX_LINE_CHARS around the match (or the start), remapping the match columns."""
    if len(raw) <= _MAX_LINE_CHARS:
        return raw, col
    if col:
        half = _MAX_LINE_CHARS // 2
        s = max(0, col[0] - half)
        e = min(len(raw), col[1] + half)
        pre, suf = ("…" if s > 0 else ""), ("…" if e < len(raw) else "")
        return pre + raw[s:e] + suf, [len(pre) + col[0] - s, len(pre) + col[1] - s]
    return raw[:_MAX_LINE_CHARS] + "…", None


def _snippet(abspath: str, line, match_text):
    """A few lines of source context around a finding's location, with the matched span
    located for highlighting. Best-effort: unreadable file / no line → None. Minified
    lines are windowed so the snippet never dumps a 50KB line."""
    if not abspath or not line or line < 1:
        return None
    try:
        text = Path(abspath).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    lines = text.splitlines()
    if line > len(lines):
        return None
    lo, hi = max(1, line - _CONTEXT_LINES), min(len(lines), line + _CONTEXT_LINES)
    out = []
    for n in range(lo, hi + 1):
        raw = lines[n - 1]
        col = None
        if n == line and match_text:
            idx = raw.find(match_text)
            if idx >= 0:
                col = [idx, idx + len(match_text)]
        txt, col = _window_line(raw, col)
        out.append({"n": n, "text": txt, "match": n == line, "col": col})
    return {"startLine": lo, "matchLine": line, "lines": out}


def _obs_to_dict(o, file_map: dict) -> dict:
    ev = {"summary": o.summary, "matchedText": o.evidence}
    snip = _snippet(file_map.get(o.path), o.line, o.evidence)
    if snip:
        ev["snippet"] = snip
    return {
        "id": o.id,
        "atom": o.atom,
        "method": o.method,
        "confidence": o.confidence,
        "location": {"path": o.path, "line": o.line},
        "evidence": ev,
        "relationships": list(o.relationships or []),
    }


def build_assessment(findings, observations, inv, target_path: str) -> dict:
    # logical rel → on-disk path, so evidence can carry a real code-context snippet.
    file_map = {f.rel: f.path for f in getattr(inv, "files", [])}
    obs_dicts = [_obs_to_dict(o, file_map) for o in observations]
    obs_by_id = {o["id"]: o for o in obs_dicts if o.get("id")}

    cited, seen = [], set()
    for f in findings:
        for oid in f.get("evidence", []):
            if oid in obs_by_id and oid not in seen:
                seen.add(oid)
                cited.append(obs_by_id[oid])

    hi_sev = _max_severity(findings)
    hi_conf = _max_confidence(findings)
    binaries = inv.binaries()

    summary = {
        "findingCount": len(findings),
        "highestSeverity": hi_sev,
        "highestConfidence": (round(hi_conf, 2) if hi_conf is not None else None),
        "highestConfidenceLabel": _confidence_label(hi_conf),
        "compositions": sorted({f["composition"] for f in findings if f.get("composition")}),
        "filesScanned": len(inv.source_files()),
        "binaryArtifacts": len(binaries),
        "binaryArtifactsWithHits": 0,
        "relatedFindingCount": 0,
        "relatedByLens": {},
    }

    correlations = _correlate(findings, obs_by_id)
    reach = {}
    disposition = _disposition(findings, correlations, reach)
    review_leads = _review_leads(reach)
    exec_text = _exec_summary(summary, findings, correlations, disposition, reach)

    deep = getattr(inv, "deep_analysis", None) or {}
    coverage_notes = [_OFFLINE_ENRICHMENT_NOTE, _IMPLEMENTATION_NOTE]
    if deep.get("enabled"):
        coverage_notes.append(
            "Optional Joern deep static analysis: "
            f"{deep.get('status', 'unknown')} over {len(deep.get('frontends') or [])} "
            "selected frontend(s); one CPG per frontend, with no cross-language flow claim."
        )
        if deep.get("implicitSinkPaths"):
            coverage_notes.append(
                f"Joern returned {deep['implicitSinkPaths']} implicit-sink slice(s); these "
                "were preserved as structural context and not treated as proven data flow."
            )
        if deep.get("unresolved"):
            coverage_notes.append(
                f"Joern reported {deep['unresolved']} unresolved node(s); see deepStaticAnalysis coverage."
            )

    return {
        "schemaVersion": ASSESSMENT_VERSION,
        "kind": "mcd-assessment",
        "assessment": {"scanner": SCANNER, "scannerVersion": SCANNER_VERSION},
        "target": {"path": str(target_path)},
        "generatedFrom": {"lens": MCD_LENS, "lensesRun": [MCD_LENS]},
        "summary": summary,
        "disposition": disposition,
        "executiveSummary": {"text": exec_text, "author": "engine"},
        "reviewLeads": review_leads,
        "findings": findings,
        "enrichment": [],
        "enrichmentProviders": [],
        "observations": cited,
        "binaries": [{"path": b.rel} for b in binaries],
        "reachability": reach,
        "correlations": correlations,
        "dynamicVerification": {"status": "not-run", "reason": "static analysis only"},
        "coverage": {
            "lensesRun": [MCD_LENS],
            "observationCount": len(obs_dicts),
            "notes": coverage_notes,
            "deepStaticAnalysis": deep,
        },
        "contract": {"note": _CONTRACT_NOTE},
    }

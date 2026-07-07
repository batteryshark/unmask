"""Project-scope MCD assessment: point it at a scan, get a correlated,
verdict-oriented report. Split into common / correlate / disposition / render;
this module orchestrates them and re-exports the public + adjudicate-facing API."""

from __future__ import annotations

from .common import *  # noqa: F401,F403
from .correlate import _correlate
from .disposition import _disposition, _exec_summary, _review_leads  # noqa: F401
from .render import render_markdown, render_html, _review_md, _adjudication_md, _finding_sort_key  # noqa: F401

def build_assessment(report: dict, lens: str = MCD_LENS) -> dict:
    """Project a scan-report dict into an MCD assessment dict."""
    all_findings = report.get("findings", [])
    findings = [f for f in all_findings if f.get("lens") == lens]
    # Findings from other lenses are NOT malicious-code shapes, but their presence
    # means "0 mcd findings" must not be read as "safe". Carry a count + a pointer.
    related = [f for f in all_findings if f.get("lens") != lens]
    related_by_lens = {}
    for f in related:
        key = f.get("lens") or "?"
        related_by_lens[key] = related_by_lens.get(key, 0) + 1

    # Carry only the observations these findings cite, so the assessment stands
    # alone: it can render its own evidence without the full scan report.
    obs_by_id = {o["id"]: o for o in report.get("observations", [])}
    cited, seen = [], set()
    for f in findings:
        for oid in f.get("evidence", []):
            if oid in obs_by_id and oid not in seen:
                seen.add(oid)
                cited.append(obs_by_id[oid])

    # Enrichment: contextual facts that adjust confidence (never severity, never
    # the finding set). The mechanism is product-neutral (in engine.enrichment); mcd
    # passes its composition_map so each fact also names the BP-* compositions it
    # touches. The confidence math keys off atom families, not compositions.
    from engine import enrichment as enrichment_mod
    from mcd_lens.enrichment_map import COMPOSITIONS_BY_FACT
    enrich = enrichment_mod.derive(report, composition_map=COMPOSITIONS_BY_FACT)
    findings = enrichment_mod.apply(findings, enrich, obs_by_id)
    enrichment_providers = enrichment_mod.provider_status(report)

    binaries = report.get("binaries", []) or []
    bin_with_hits = sum(1 for b in binaries if b.get("stringObservations"))

    hi_sev = _max_severity(findings)            # how bad if real
    hi_conf = _max_confidence(findings)         # how sure (kept separate, on purpose)

    cov_notes = list(report.get("notes", []))
    for note in enrichment_mod.provider_notes(report):
        if note not in cov_notes:
            cov_notes.append(note)
    note = runtime_mod.coverage_note()
    if note not in cov_notes:
        cov_notes.append(note)
    cov_notes.append(_IMPLEMENTATION_NOTE)
    if related:
        bits = ", ".join(f"{n} {l}" for l, n in sorted(related_by_lens.items()))
        cov_notes.append(
            "This assessment covers malicious-code (mcd) shapes only. The scan also surfaced "
            f"{len(related)} finding(s) under other lenses ({bits}); review those for that "
            "view. Absence of mcd findings is not a safety verdict.")

    summary = {
        "findingCount": len(findings),
        "highestSeverity": hi_sev,
        "highestConfidence": (round(hi_conf, 2) if hi_conf is not None else None),
        "highestConfidenceLabel": _confidence_label(hi_conf),
        "compositions": sorted({f["composition"] for f in findings if f.get("composition")}),
        "filesScanned": report.get("summary", {}).get("filesScanned"),
        "binaryArtifacts": len(binaries),
        "binaryArtifactsWithHits": bin_with_hits,
        "relatedFindingCount": len(related),
        "relatedByLens": related_by_lens,
    }
    correlations = _correlate(findings, obs_by_id)
    reach = report.get("reachability") or {}
    disposition = _disposition(findings, correlations, reach)
    review_leads = _review_leads(reach)
    exec_text = _exec_summary(summary, findings, correlations, disposition, reach)
    dynamic_verification = report.get("dynamicVerification") or runtime_mod.build_status(findings)

    return {
        "schemaVersion": ASSESSMENT_VERSION,
        "kind": "mcd-assessment",
        "assessment": {
            "id": f"assess-{uuid.uuid4().hex[:12]}",
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "scanner": SCANNER,
            "scannerVersion": __version__,
        },
        "target": report.get("target", {}),
        "generatedFrom": {
            "scanId": report.get("scan", {}).get("id"),
            "scannerVersion": report.get("scan", {}).get("scannerVersion"),
            "lens": lens,
            "lensesRun": report.get("lenses", []),
        },
        "summary": summary,
        "disposition": disposition,
        "executiveSummary": {"text": exec_text, "author": "engine"},
        "reviewLeads": review_leads,
        "findings": findings,
        "enrichment": enrich,
        "enrichmentProviders": enrichment_providers,
        "observations": cited,
        "binaries": binaries,
        "reachability": reach,
        "correlations": correlations,
        "dynamicVerification": dynamic_verification,
        "coverage": {
            "lensesRun": report.get("lenses", []),
            "observationCount": report.get("summary", {}).get(
                "observationCount", len(report.get("observations", []))),
            "notes": cov_notes,
        },
        "contract": {"note": _CONTRACT_NOTE},
    }


def to_json(assessment: dict) -> str:
    return json.dumps(assessment, indent=2)

"""Native build_assessment: project native observations + findings into an MCD
assessment dict (disposition, summary, correlations, coverage).

Rebuilt clean over the native pipeline (no engine scan-report dependency).
Enrichment (contextual confidence adjustment via external providers) is offline in
core, so it is a no-op here plus a coverage note; the deterministic disposition,
severity/confidence separation, and correlation are preserved exactly.
"""

from __future__ import annotations

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


def _obs_to_dict(o) -> dict:
    return {
        "id": o.id,
        "atom": o.atom,
        "method": o.method,
        "confidence": o.confidence,
        "location": {"path": o.path, "line": o.line},
        "evidence": {"summary": o.summary, "matchedText": o.evidence},
        "relationships": list(o.relationships or []),
    }


def build_assessment(findings, observations, inv, target_path: str) -> dict:
    obs_dicts = [_obs_to_dict(o) for o in observations]
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
            "notes": [_OFFLINE_ENRICHMENT_NOTE, _IMPLEMENTATION_NOTE],
        },
        "contract": {"note": _CONTRACT_NOTE},
    }

"""Disposition: the deterministic quarantine / review / clear rule, the top verify
questions, and the deterministic executive summary."""

from __future__ import annotations

from .common import *  # noqa: F401,F403

_QUARANTINE_MIN_CONF = 0.65

_THRESHOLD_NOTE = (
    "Disposition rule (deterministic; severity and confidence kept separate): quarantine if any "
    "high/critical-severity finding has proof-aware confidence >= 0.65, or a cross-signal correlated "
    "cluster is high/critical severity. Findings whose proof depth is only same-file co-occurrence "
    "or co-location are not promoted to quarantine by enrichment alone. Review if mcd findings exist "
    "but do not meet that bar; clear if there are no mcd findings. The model never sets the disposition.")


def _top_questions(findings, n=3):
    seen, out = set(), []
    for f in sorted(findings, key=lambda x: -_rank(x.get("severity"))):
        for v in f.get("verification", []):
            q = (v.get("question") or "").strip()
            if q and q not in seen:
                seen.add(q)
                out.append(q)
            if len(out) >= n:
                return out
    return out


def _proof_limited(finding: dict) -> bool:
    text = " ".join(str(item or "") for item in finding.get("attenuators", [])).lower()
    if not text:
        return False
    return (
        ("proof depth:" in text or "tool routing is not proven" in text)
        and (
            "same-file co-occurrence" in text
            or "same-file co-location" in text
            or "same-file or explicit tool-surface co-location" in text
            or "not proven" in text
        )
    )


def _disposition_confidence(finding: dict) -> float:
    base = finding.get("confidence") or 0
    effective = finding.get("effectiveConfidence", base) or 0
    # Local enrichment can raise attention around supply-chain drift, but it does
    # not prove value flow, reachability, or malicious intent for co-occurrence-only
    # findings. Keep quarantine decisions tied to the proof depth.
    if _proof_limited(finding):
        return min(base, effective)
    return effective


def _disposition(findings, correlations, reachability=None):
    """Map findings + correlations to clear / review / quarantine by a stated rule."""
    # Narrow, low-false-positive cross-file signal: an entry reaches BOTH network
    # egress/fetch AND code execution across files (the split-dropper shape that
    # single-file co-occurrence cannot see).
    xsinks = (reachability or {}).get("reachableSinks") or []
    xkinds = {k for s in xsinks if s.get("crossFile") for k in s.get("sinkKinds", [])}
    split = ("exec" in xkinds) and ("egress" in xkinds or "fetch" in xkinds)

    if not findings:
        if split:
            return {
                "recommendation": "review",
                "rationale": ("No single-file malicious-code finding, but the call graph reaches both "
                              "network egress/fetch and code execution across files from a package entry "
                              "point: the split-dropper shape that per-file co-occurrence cannot see. "
                              "Review the cross-file chain."),
                "drivers": ["cross-file reachable exec + egress/fetch from a package entry (chain split across files)"],
                "thresholds": _THRESHOLD_NOTE,
            }
        return {
            "recommendation": "clear",
            "rationale": ("No malicious-code (mcd) findings. This is 'clear of mcd findings', not a "
                          "guarantee of safety; read the coverage section for implemented composition "
                          "coverage and, if other lenses fired, the related-signals note."),
            "drivers": [],
            "thresholds": _THRESHOLD_NOTE,
        }
    high_bar = _rank("high")
    high_conf = [f for f in findings
                 if _rank(f.get("severity")) >= high_bar
                 and _disposition_confidence(f) >= _QUARANTINE_MIN_CONF]
    cross_high = [c for c in correlations
                  if c.get("crossSignal") and _rank(c.get("severity")) >= high_bar]
    if high_conf or cross_high:
        drivers = []
        if high_conf:
            drivers.append(f"{len(high_conf)} high/critical-severity finding(s) at proof-aware confidence "
                           f">= {_QUARANTINE_MIN_CONF}")
        if cross_high:
            drivers.append(f"{len(cross_high)} cross-signal correlated cluster(s) at high/critical "
                           "severity (corroborated co-location)")
        return {
            "recommendation": "quarantine",
            "rationale": ("Recommend quarantine: " + "; ".join(drivers) + ". Quarantine means hold the "
                          "artifact and do not install or run it until the verification questions are "
                          "answered. This is a recommended next-action from the evidence, not a "
                          "maliciousness verdict; severity and confidence are reported separately."),
            "drivers": drivers,
            "thresholds": _THRESHOLD_NOTE,
        }
    if any(_rank(f.get("severity")) >= high_bar for f in findings):
        why = "high-severity findings exist but below the quarantine confidence bar"
    else:
        why = "no high/critical-severity findings"
    return {
        "recommendation": "review",
        "rationale": (f"Recommend review: malicious-code findings are present but do not meet the "
                      f"quarantine bar ({why}). Have an engineer resolve the verification questions "
                      "before relying on the code."),
        "drivers": [why],
        "thresholds": _THRESHOLD_NOTE,
    }


def _review_leads(reachability=None):
    """Evidence-backed review leads that are not single-file MCD findings.

    These keep `findingCount` precise while making disposition drivers visible in
    the first screen. The first use is the split-dropper reachability shape: a
    package entry reaches network fetch/egress and execution across files, so no
    one file contains enough co-occurrence for a finding, but the chain still
    deserves human review.
    """
    reachability = reachability or {}
    xsinks = [s for s in reachability.get("reachableSinks", []) if s.get("crossFile")]
    kinds = {k for s in xsinks for k in s.get("sinkKinds", [])}
    split = ("exec" in kinds) and ("egress" in kinds or "fetch" in kinds)
    if not split:
        return []
    return [{
        "id": "lead-cross-file-split-dropper",
        "kind": "cross-file-reachability",
        "title": "Cross-file reachable fetch/egress + execution chain",
        "claim": (
            "A package entry reaches network fetch or egress and code execution across files. "
            "No single file contains the full malicious-code shape, but the reachable chain is "
            "the split-dropper pattern that should be reviewed."
        ),
        "severity": "high",
        "confidence": 0.65,
        "disposition": "review",
        "drivers": ["cross-file reachable exec + egress/fetch from a package entry"],
        "evidence": [
            {
                "file": s.get("file"),
                "function": s.get("function"),
                "sinkKinds": list(s.get("sinkKinds") or []),
                "entryFile": s.get("entryFile"),
                "chain": list(s.get("chain") or []),
            }
            for s in xsinks if set(s.get("sinkKinds") or []) & {"exec", "egress", "fetch"}
        ],
        "verify": [
            "Can package installation or another entry point actually trigger both branches?",
            "What remote content or destination is reached before execution?",
            "Is execution sandboxed, integrity-checked, or otherwise constrained?",
        ],
        "disproof": [
            "The entry point cannot reach one side of the chain in a real run.",
            "The network branch is a fixed benign service and never feeds execution.",
            "Execution is unreachable, inert, test-only, or gated by an explicit safe workflow.",
        ],
    }]


def _exec_summary(summary, findings, correlations, disposition, reachability=None):
    """The deterministic executive summary: the disposition, the headline numbers
    (severity and confidence stated separately), the strongest signal, and what to
    verify next. A model may rephrase this prose later but never changes the facts."""
    conf = summary.get("highestConfidence")
    parts = [f"Disposition: {disposition['recommendation'].upper()}."]
    parts.append(f"{summary['findingCount']} malicious-code finding(s); highest severity "
                 f"{summary['highestSeverity'] or 'none'}, highest confidence "
                 f"{conf if conf is not None else 'n/a'} (severity and confidence are independent).")
    if correlations:
        parts.append("Strongest correlation: " + correlations[0]["narrative"])
    elif findings:
        f = max(findings, key=lambda x: _rank(x.get("severity")))
        parts.append(f"Sharpest finding: [{f.get('severity')}] {f.get('title')}.")
    qs = _top_questions(findings, 3)
    if qs:
        parts.append("Verify next: " + " ".join(f"({i + 1}) {q}" for i, q in enumerate(qs)))
    if summary.get("relatedFindingCount"):
        if summary.get("findingCount", 0) == 0:
            parts.append(f"Note: {summary['relatedFindingCount']} finding(s) under other lenses "
                         "exist, so this is not a safety verdict; see the risk map.")
        else:
            parts.append(f"Also: {summary['relatedFindingCount']} finding(s) under other lenses "
                         "(not malicious-code shapes); see the risk map.")
    xsinks = [s for s in (reachability or {}).get("reachableSinks", []) if s.get("crossFile")]
    if xsinks:
        kinds = sorted({k for s in xsinks for k in s["sinkKinds"]})
        parts.append(f"Cross-file reachability: {', '.join(kinds)} sink(s) reachable from a package "
                     "entry across files (see the reachability section).")
    return " ".join(parts)

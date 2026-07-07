"""Adjudication overlay: fold reviewer verdicts into a *reviewed* disposition.

The engine owns the authoritative, severity-aware disposition. This overlay adds
a second, review-derived recommendation computed by a DETERMINISTIC rule over the
reviewers' verdicts and confidences — the model judges each finding, but the model
never sets the disposition. Ported from the mcd-report adjudication logic.
"""

from __future__ import annotations

from unmask.reviewers.agent import build_reviewer, review_finding
from unmask.reviewers.schemas import FindingReview

_RESPONSE_TIERS = {
    0: ("close", "No action: the finding is closed out."),
    1: ("document", "Document the finding and move on; no engineering change needed."),
    2: ("engineering-referral", "Refer to engineering for a fix or a design change."),
    3: ("passive-monitoring", "Keep the artifact under passive monitoring."),
    4: ("active-monitoring", "Put the artifact under active monitoring and review."),
    5: ("immediate", "Immediate action: hold, isolate, or remediate now."),
}
_REVIEWED_QUARANTINE_MIN_CONF = 0.65
_STANDING = {"confirm", "escalate", "deescalate"}
_QUARANTINE_VERDICTS = {"confirm", "escalate"}


def _reviewed_disposition(non_excluded: list[FindingReview]) -> dict:
    quarantine = [r for r in non_excluded
                  if r.verdict in _QUARANTINE_VERDICTS
                  and r.reviewed_confidence >= _REVIEWED_QUARANTINE_MIN_CONF]
    if quarantine:
        return {"recommendation": "quarantine",
                "rationale": (f"{len(quarantine)} finding(s) confirmed/escalated at reviewed "
                              f"confidence >= {_REVIEWED_QUARANTINE_MIN_CONF}. Hold the artifact "
                              "until the verification questions are answered.")}
    live = [r for r in non_excluded if r.verdict in _STANDING]
    if live:
        return {"recommendation": "review",
                "rationale": (f"{len(live)} malicious-code finding(s) survived review (confirmed, "
                              "escalated, or de-escalated) but do not meet the quarantine bar.")}
    return {"recommendation": "clear",
            "rationale": ("The reviewer refuted or suppressed every finding that counts toward "
                          "disposition. Clear of standing mcd findings, not a full safety guarantee.")}


def adjudicate(assessment: dict, reviews: list[FindingReview]) -> dict | None:
    if not reviews:
        return None
    findings_by_id = {f.get("id"): f for f in assessment.get("findings", [])}
    counts: dict[str, int] = {}
    moved = []
    for r in reviews:
        counts[r.verdict] = counts.get(r.verdict, 0) + 1
        eng = findings_by_id.get(r.finding_id, {}).get("confidence")
        if eng is not None and r.reviewed_confidence != eng:
            moved.append({"findingId": r.finding_id, "decision": r.verdict,
                          "originalConfidence": eng, "reviewedConfidence": r.reviewed_confidence})

    non_excluded = [r for r in reviews if not r.excluded_from_disposition]
    tiers = [r.response_tier for r in non_excluded]
    if tiers:
        top = max(tiers)
        name, summary = _RESPONSE_TIERS.get(top, ("unknown", "Unrecognized response tier."))
        response_level = {"tier": top, "name": name, "summary": summary}
    else:
        response_level = None

    reviewed = _reviewed_disposition(non_excluded)
    engine_disp = (assessment.get("disposition") or {}).get("recommendation")
    return {
        "note": ("Agentic review overlaid on the deterministic scan: the engine found the shapes; "
                 "the reviewer read the evidence behind each and set verdicts and confidence."),
        "counts": counts,
        "moved": moved,
        "responseLevel": response_level,
        "reviewedDisposition": reviewed,
        "engineDisposition": engine_disp,
        "dispositionChanged": reviewed["recommendation"] != engine_disp,
        "reviews": [r.model_dump() for r in reviews],
    }


def _evidence_for(finding: dict, obs_by_id: dict) -> list[dict]:
    return [obs_by_id[oid] for oid in finding.get("evidence", []) if oid in obs_by_id]


def review_assessment(assessment: dict, *, model=None, agent=None,
                      only_severities: set[str] | None = None) -> tuple[list[FindingReview], dict | None]:
    """Review the assessment's findings and return (reviews, adjudication overlay).

    `only_severities` limits which findings are sent to the model (e.g. {"high",
    "critical"}); default reviews all. Reviewers only judge existing findings.
    """
    agent = agent or build_reviewer(model)
    obs_by_id = {o.get("id"): o for o in assessment.get("observations", [])}
    reviews: list[FindingReview] = []
    for f in assessment.get("findings", []):
        if only_severities and f.get("severity") not in only_severities:
            continue
        reviews.append(review_finding(f, _evidence_for(f, obs_by_id), agent=agent))
    return reviews, adjudicate(assessment, reviews)

"""Adversarial verification of review DOWNGRADES.

A reviewer that CONFIRMS a finding costs nothing if it is wrong — the finding still
stands. A reviewer that DOWNGRADES one (refute / suppress / deescalate) silently removes
or weakens a real finding: that is exactly where recall dies to a single model opinion.
So every downgrade faces a quorum of *perspective-diverse* skeptics, each prompted to
OVERTURN it (defend the finding). A downgrade stands only if a majority upholds it;
otherwise it reverts to the engine's stance — the finding is kept and flagged
`needs_human`, never silently cleared. This is the engine's adversarial-verify pattern
applied to the one layer that is silent model judgment. (Verifier role: `verifier` — a
step that wants a strong model when per-role routing lands.)
"""

from __future__ import annotations

from unmask.reviewers.adjudicate import _evidence_for
from unmask.reviewers.schemas import FindingReview, VerifyVote

# Verdicts that weaken/remove a finding — the only ones worth verifying (confirming a
# finding never loses recall).
_SOFTENING = {"refute", "suppress", "deescalate"}

_VERIFY_BASE = (
    "A first reviewer DOWNGRADED a static-analysis finding (refute/suppress/deescalate), "
    "which removes or weakens it. Your job is to decide whether that downgrade is JUSTIFIED "
    "or whether the finding is actually real. Default to OVERTURN when uncertain — a wrongly "
    "kept finding is cheap, a wrongly dropped one is a miss. Return uphold or overturn.\n\n"
)

# Perspective-diverse lenses so the votes catch different failure modes, not the same one
# three times.
_LENSES = (
    ("evidence",
     "LENS: the evidence. Look ONLY at the cited evidence. Overturn if it still shows the "
     "malicious-code shape the finding claims; uphold only if the evidence genuinely reads benign."),
    ("attacker",
     "LENS: the attacker. Would real malware plausibly produce exactly this pattern? Overturn "
     "if it would; uphold only if this is implausible for an attacker to write."),
    ("false-positive",
     "LENS: the benign explanation. Name the SPECIFIC benign pattern (a known library, a test "
     "fixture, a framework idiom) that explains this. Uphold ONLY if you can name it concretely; "
     "overturn if you cannot."),
)


def build_verifier(lens_instruction: str, model=None):
    from pydantic_ai import Agent

    if model is None:
        from unmask.reviewers.config import ReviewModelConfig
        model = ReviewModelConfig.from_env().build_model()
    return Agent(model, output_type=VerifyVote, instructions=_VERIFY_BASE + lens_instruction, retries=2)


def _prompt(finding: dict, evidence: list[dict], review: FindingReview) -> str:
    lines = [
        f"Finding {finding.get('id')}: {finding.get('title')}  [{finding.get('composition')}]",
        f"Claim: {finding.get('claim')}",
        f"First reviewer's downgrade: {review.verdict} — {review.justification}",
        "",
        "Cited evidence (atom @ file:line — matched text):",
    ]
    for o in evidence:
        loc = o.get("location") or {}
        ev = o.get("evidence")
        if isinstance(ev, dict):
            ev = ev.get("matchedText") or ev.get("summary")
        lines.append(f"- {o.get('atom')} @ {loc.get('path')}:{loc.get('line')} — {ev}")
    lines += ["", "Decide: uphold the downgrade, or overturn it (the finding is real)?"]
    return "\n".join(lines)


def _vote(finding: dict, evidence: list[dict], review: FindingReview, *, model, agents=None) -> list[dict]:
    votes: list[dict] = []
    for i, (name, lens) in enumerate(_LENSES):
        agent = agents[i] if agents else build_verifier(lens, model)
        try:
            v: VerifyVote = agent.run_sync(_prompt(finding, evidence, review)).output
            votes.append({"lens": name, "decision": v.decision, "rationale": v.rationale})
        except Exception as exc:  # a dead verifier defends the finding — bias toward recall
            votes.append({"lens": name, "decision": "overturn", "rationale": f"verifier unavailable: {exc!r}"})
    return votes


def verify_downgrades(reviews: list[FindingReview], assessment: dict, *, model=None, agents=None):
    """Verify every downgrade review with a quorum of perspective-diverse skeptics.

    Returns ``(adjusted_reviews, records)``. A downgrade that a majority overturns reverts
    to the engine's stance: the finding is kept, `needs_human`, not excluded — never
    silently cleared. ``agents`` (a list matching `_LENSES`) is injectable for tests.
    """
    findings_by_id = {f.get("id"): f for f in assessment.get("findings", [])}
    obs_by_id = {o.get("id"): o for o in assessment.get("observations", []) if o.get("id")}
    adjusted: list[FindingReview] = []
    records: list[dict] = []
    for r in reviews:
        finding = findings_by_id.get(r.finding_id)
        if r.verdict not in _SOFTENING or finding is None:
            adjusted.append(r)
            continue
        votes = _vote(finding, _evidence_for(finding, obs_by_id), r, model=model, agents=agents)
        overturn = sum(1 for v in votes if v["decision"] == "overturn")
        stands = overturn < (len(votes) + 1) // 2  # majority overturn drops the downgrade
        if stands:
            adjusted.append(r)
            outcome = "upheld"
        else:
            adjusted.append(r.model_copy(update={
                "verdict": "needs_human", "excluded_from_disposition": False,
                "justification": r.justification + " [downgrade overturned by adversarial verify]"}))
            outcome = "overturned"
        records.append({"findingId": r.finding_id, "originalVerdict": r.verdict,
                        "outcome": outcome, "overturnVotes": overturn, "votes": votes})
    return adjusted, records

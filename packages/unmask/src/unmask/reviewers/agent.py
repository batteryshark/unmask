"""The bounded finding reviewer (pydantic-ai).

One finding in, one typed `FindingReview` out. The model reads the finding's
evidence and returns a verdict + a policy-bounded confidence; it never writes
report prose, never changes severity, and never decides completion. Any failure
(unreachable endpoint, malformed output) degrades to a `needs_human` review that
keeps the finding flagged — never a silent drop.
"""

from __future__ import annotations

from unmask.reviewers.config import ReviewModelConfig
from unmask.reviewers.schemas import FindingReview

REVIEW_INSTRUCTIONS = (
    "You are a malicious-code review analyst. You are given ONE static-analysis finding "
    "(a BP-* malicious-code shape) and the exact evidence it cites. Decide, from the "
    "evidence alone, whether the shape is real.\n\n"
    "Rules:\n"
    "- Judge only THIS finding. Do not invent evidence beyond what is cited.\n"
    "- Verdicts: confirm (real), escalate (real and worse than stated), deescalate (real "
    "but weaker/likely-benign context), refute (not a malicious-code shape), suppress "
    "(rule noise / false positive), needs_evidence (must fetch/decode more to decide), "
    "needs_human (genuinely ambiguous).\n"
    "- Be adversarial toward the FINDING, not the code: if the cited evidence does not "
    "actually support the shape, refute or deescalate. Do not confirm on vibes.\n"
    "- Set reviewed_confidence in [0,1] and response_tier in [0..5]. Severity is fixed by "
    "the engine; you do not change it. Set excluded_from_disposition=true for refute/suppress.\n"
    "- Give a concrete justification that cites the evidence, and list which disproof "
    "criteria you actually checked. Propose followups only when they would change the verdict."
)


def build_reviewer(model=None):
    """An Agent that emits a validated FindingReview. `model` may be a pydantic-ai
    model (incl. TestModel for tests); default resolves one from the environment."""
    from pydantic_ai import Agent

    if model is None:
        model = ReviewModelConfig.from_env().build_model()
    return Agent(model, output_type=FindingReview, instructions=REVIEW_INSTRUCTIONS, retries=2)


# A single cited snippet can be a whole minified/obfuscated line — hundreds of KB.
# The reviewer only needs a representative sample to judge the match; the full blob
# would blow past the model's context window (a 400KB line ~= 130K tokens). Clip it.
MAX_EVIDENCE_CHARS = 600


def _clip(ev, limit: int = MAX_EVIDENCE_CHARS) -> str:
    s = "" if ev is None else str(ev)
    return s if len(s) <= limit else f"{s[:limit]}…[+{len(s) - limit} chars clipped]"


def _evidence_line(o: dict) -> str:
    loc = o.get("location") or {}
    ev = o.get("evidence")
    if isinstance(ev, dict):
        ev = ev.get("matchedText") or ev.get("summary")
    return f"- {o.get('atom')} @ {loc.get('path')}:{loc.get('line')} — {_clip(ev)}"


def build_prompt(finding: dict, evidence: list[dict]) -> str:
    lines = [
        f"Finding {finding.get('id')}: {finding.get('title')}  [{finding.get('composition')}]",
        f"Engine severity: {finding.get('severity')} · engine confidence: {finding.get('confidence')}",
        f"Claim: {finding.get('claim')}",
        "",
        "What would disprove this finding:",
        *[f"- {d}" for d in finding.get("disproofCriteria", [])],
        "",
        "Open verification questions:",
        *[f"- {v.get('question')}" for v in finding.get("verification", [])],
        "",
        "Cited evidence (atom @ file:line — matched text):",
        *[_evidence_line(o) for o in evidence],
        "",
        f"Review finding {finding.get('id')}: read the evidence, pick the verdict, set "
        "reviewed_confidence and response_tier, and justify against the disproof criteria.",
    ]
    return "\n".join(lines)


def review_finding(finding: dict, evidence: list[dict], *, agent=None, model=None) -> FindingReview:
    agent = agent or build_reviewer(model)
    try:
        result = agent.run_sync(build_prompt(finding, evidence))
        fr: FindingReview = result.output
        if fr.finding_id != finding.get("id"):
            fr = fr.model_copy(update={"finding_id": finding.get("id", "")})
        return fr
    except Exception as exc:  # unreachable endpoint / malformed output → keep it, flagged
        return FindingReview(
            finding_id=finding.get("id", ""),
            verdict="needs_human",
            reviewed_confidence=float(finding.get("confidence") or 0.0),
            response_tier=int((finding.get("response") or {}).get("tier", 3)),
            justification=f"reviewer unavailable or malformed output: {exc!r}",
        )

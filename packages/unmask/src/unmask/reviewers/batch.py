"""Batched finding review via a pydantic-ai record tool.

The single-finding reviewer (``agent.py``) calls ``run_sync`` once per finding —
correct but unbounded on a 50+ finding run: each call is a full model turn, so a
large scan hits N round-trips and N chances to hit an output-size limit before
finishing. The batch reviewer feeds findings in CHUNKS and has the model emit one
verdict per finding through a sequential ``record_finding_review`` tool, so a chunk
of K findings drains in a bounded number of turns regardless of K. This is the
shape ``docs/design.md`` specifies ("Use record tools for batch review so coverage
is not limited by final output size").

Contract (unchanged from the single-finding reviewer):
  * every finding gets a verdict — nothing is silently dropped;
  * a finding the model skips or returns malformed output for becomes ``needs_human``
    (keeps the finding flagged, never a silent clear);
  * the model never sets disposition — the deterministic adjudication overlay does.

Usage:
    agent, reviews = build_batch_reviewer(model)
    review_assessment_batched(assessment, agent=agent, reviews=reviews)

For small assessments (≤ ``SINGLE_REVIEW_THRESHOLD``) the single-finding path is
cheaper and is used automatically; the batch path is for larger runs.
"""

from __future__ import annotations

from unmask.reviewers.adjudicate import _evidence_for, adjudicate
from unmask.reviewers.agent import (
    REVIEW_INSTRUCTIONS, _ev_text, build_reviewer, render_evidence,
)
from unmask.reviewers.schemas import FindingReview

# Below this finding count the single-finding reviewer (one run_sync per finding)
# is cheaper than spinning up the batch tool loop. Above it, batching wins.
SINGLE_REVIEW_THRESHOLD = 6
# Findings per model turn in the batch loop. Bounded so the prompt + the model's
# record-tool calls stay well under any output-token cap.
BATCH_SIZE = 10
# Hard ceiling on batch-loop turns across the whole assessment — a runaway model
# can't loop forever; unreviewed findings at the cap become needs_human.
MAX_BATCH_TURNS = 30

_BATCH_INSTRUCTIONS = (
    REVIEW_INSTRUCTIONS
    + "\n\n"
    "BATCH MODE: you are given a CHUNK of findings at once. For EACH finding, call "
    "the `record_finding_review` tool exactly once with your verdict. Do not skip any "
    "finding in the chunk. Process them one at a time, citing each finding's id. When "
    "you have recorded a review for every finding in the chunk, you are done with that "
    "chunk — do not add prose. A finding you genuinely cannot judge gets verdict "
    "`needs_human`, never a skip.\n\n"
    "TOOL — expand_evidence(observation_id, offset=0): supporting matches are shown "
    "clipped. When the clipped preview is not enough to rule — you must read a full "
    "obfuscated blob, decode a value, or check whether a fetched value flows into exec — "
    "call expand_evidence with that observation's id to page its full content (6000 chars "
    "per call; use offset to page further). Recovered payloads are already shown in full."
)


def _expand_evidence(obs_by_id: dict | None, observation_id: str,
                     offset: int = 0, window: int = 6000) -> dict:
    """Page the full evidence of a cited observation (what the expand_evidence tool
    returns). Bounded to `window` chars per call; the model pages with `offset`."""
    o = (obs_by_id or {}).get(observation_id)
    if not o:
        return {"error": f"no observation {observation_id!r}"}
    ev = _ev_text(o)
    return {"observation_id": observation_id, "atom": o.get("atom"),
            "offset": offset, "total_len": len(ev),
            "content": ev[offset:offset + window], "has_more": offset + window < len(ev)}


def build_batch_reviewer(model=None, obs_by_id=None):
    """Construct a batch reviewer Agent + the list it will record into.

    Returns ``(agent, reviews)``: the agent records each verdict into ``reviews``
    via the sequential ``record_finding_review`` tool. The caller drives the agent
    chunk-by-chunk and then reads ``reviews``.
    """
    from pydantic_ai import Agent

    if model is None:
        from unmask.reviewers.config import ReviewModelConfig
        model = ReviewModelConfig.from_env().build_model()

    reviews: list[FindingReview] = []

    agent = Agent(model, instructions=_BATCH_INSTRUCTIONS, retries=1)

    @agent.tool_plain(name="record_finding_review", sequential=True)
    def _record(review: FindingReview) -> dict:
        reviews.append(review)
        return {"recorded": review.finding_id, "total_recorded": len(reviews)}

    if obs_by_id:
        @agent.tool_plain(name="expand_evidence")
        def _expand(observation_id: str, offset: int = 0) -> dict:
            """Read the full content of a cited observation when its clipped preview is
            not enough to rule (an obfuscated blob to decode, a dataflow link to check)."""
            return _expand_evidence(obs_by_id, observation_id, offset)

    return agent, reviews


def _chunk_prompt(findings_chunk: list[dict], obs_by_id: dict) -> str:
    """Build the user prompt for one chunk of findings."""
    lines = [
        f"Review these {len(findings_chunk)} finding(s). For EACH one, call "
        "`record_finding_review` with your verdict. Do not skip any.",
        "",
    ]
    for f in findings_chunk:
        lines += [
            f"## Finding {f.get('id')}: {f.get('title')}  [{f.get('composition')}]",
            f"Engine severity: {f.get('severity')} · engine confidence: {f.get('confidence')}",
            f"Claim: {f.get('claim', '')}",
            "Disproof criteria:",
            *[f"- {d}" for d in (f.get("disproofCriteria") or [])[:3]],
            "Cited evidence:",
            *render_evidence(_evidence_for(f, obs_by_id)),
            "",
        ]
    return "\n".join(lines)


def _needs_human(finding: dict) -> FindingReview:
    """The fallback for a finding the model skipped or mis-judged: keep it flagged,
    never a silent clear/drop."""
    return FindingReview(
        finding_id=finding.get("id", ""),
        verdict="needs_human",
        reviewed_confidence=float(finding.get("confidence") or 0.0),
        response_tier=int((finding.get("response") or {}).get("tier", 3)),
        justification="Batch reviewer did not return a verdict for this finding (skipped, "
                      "malformed, or turn-limit reached); kept flagged for human review.",
    )


def review_assessment_batched(assessment: dict, *, model=None, agent=None,
                              reviews: list[FindingReview] | None = None,
                              only_severities: set[str] | None = None,
                              batch_size: int = BATCH_SIZE,
                              max_turns: int = MAX_BATCH_TURNS) -> tuple[list[FindingReview], dict | None]:
    """Review an assessment's findings in batched chunks via the record tool.

    Falls back to the single-finding reviewer for small assessments
    (≤ ``SINGLE_REVIEW_THRESHOLD`` findings). Returns ``(reviews, adjudication)``.
    """
    all_findings = assessment.get("findings", []) or []
    if only_severities:
        all_findings = [f for f in all_findings if f.get("severity") in only_severities]
    if not all_findings:
        return [], None

    # Small assessment → the cheaper single-finding path.
    if len(all_findings) <= SINGLE_REVIEW_THRESHOLD and agent is None:
        from unmask.reviewers.adjudicate import review_assessment
        return review_assessment(assessment, model=model, only_severities=only_severities)

    obs_by_id = {o.get("id"): o for o in assessment.get("observations", [])}

    if agent is None:
        agent, collected = build_batch_reviewer(model, obs_by_id=obs_by_id)
    else:
        collected = reviews if reviews is not None else []
    if collected is None:
        collected = []

    reviewed_ids: set[str] = set()
    turns = 0

    for i in range(0, len(all_findings), batch_size):
        if turns >= max_turns:
            break
        chunk = all_findings[i:i + batch_size]
        prompt = _chunk_prompt(chunk, obs_by_id)
        try:
            agent.run_sync(prompt)
        except Exception:
            # A failed chunk is not fatal — its findings fall through to needs_human.
            pass
        turns += 1
        # Track which findings in THIS chunk the model actually recorded.
        chunk_ids = {f.get("id") for f in chunk}
        for r in collected:
            if r.finding_id in chunk_ids:
                reviewed_ids.add(r.finding_id)

    # Anything the model skipped → needs_human (never a silent drop). Only reviews
    # whose finding_id matches a real finding in the assessment are kept; a model
    # that echoes a wrong/blank id does not pollute the set.
    valid_ids = {f.get("id") for f in all_findings if f.get("id")}
    out: list[FindingReview] = []
    seen: set[str] = set()
    for r in collected:
        if r.finding_id in valid_ids and r.finding_id not in seen:
            out.append(r)
            seen.add(r.finding_id)
    for f in all_findings:
        fid = f.get("id")
        if fid and fid not in seen:
            out.append(_needs_human(f))
            seen.add(fid)

    return out, adjudicate(assessment, out)


__all__ = [
    "build_batch_reviewer", "review_assessment_batched",
    "SINGLE_REVIEW_THRESHOLD", "BATCH_SIZE", "MAX_BATCH_TURNS",
]

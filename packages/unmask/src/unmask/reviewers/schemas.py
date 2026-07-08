"""Typed reviewer outputs.

Bounded judgment: a reviewer reads ONE finding's evidence and returns a narrow,
validated verdict. It may not author report prose, may not change severity (a
shape property), and may only move confidence through the deterministic
adjudication policy. Malformed/uncertain output becomes needs_review, never a
silent drop. (See docs/design.md "Pydantic AI Reviewer Design".)
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Verdict = Literal[
    "confirm",      # the malicious-code shape is real
    "escalate",     # real and worse than the engine's confidence
    "deescalate",   # real shape but weaker / likely benign context
    "refute",       # not a malicious-code shape (excluded from disposition)
    "suppress",     # rule noise / false positive (excluded from disposition)
    "needs_evidence",  # can't decide without fetching/decoding more
    "needs_human",  # genuinely ambiguous; requires a human
]

FollowupKind = Literal[
    "fetch_remote_content", "decode_payload", "decompile_artifact",
    "dynamic_plan", "human_review",
]


class FollowupRequest(BaseModel):
    kind: FollowupKind
    target: str = Field(description="URL, artifact path, or finding id the follow-up acts on")
    rationale: str
    evidence_ids: list[str] = Field(default_factory=list)


class FindingReview(BaseModel):
    finding_id: str
    verdict: Verdict
    reviewed_confidence: float = Field(ge=0.0, le=1.0)
    response_tier: int = Field(ge=0, le=5)
    excluded_from_disposition: bool = False
    justification: str
    disproof_checked: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    followups: list[FollowupRequest] = Field(default_factory=list)


class VerifyVote(BaseModel):
    """One skeptic's vote on whether a review DOWNGRADE (refute/suppress/deescalate)
    should stand. `overturn` means the downgrade is wrong and the finding is real; the
    verifier defends the finding, never re-confirms maliciousness on its own."""

    decision: Literal["uphold", "overturn"]
    rationale: str

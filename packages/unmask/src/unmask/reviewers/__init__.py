"""Agentic review — bounded, typed adjudication of findings (unmask[review]).

A pydantic-ai reviewer reads one finding's evidence and returns a validated
`FindingReview`. The model performs judgment; the deterministic adjudication
policy (not the model) recomputes disposition from the verdicts. Any OpenAI-
compatible endpoint works (LM Studio / MiniMax / z.ai-GLM / OpenAI / local).
"""

from __future__ import annotations

from unmask.reviewers.adjudicate import adjudicate, review_assessment
from unmask.reviewers.agent import build_reviewer, review_finding
from unmask.reviewers.batch import (
    BATCH_SIZE, MAX_BATCH_TURNS, SINGLE_REVIEW_THRESHOLD, build_batch_reviewer,
    review_assessment_batched,
)
from unmask.reviewers.config import ReviewConfigError, ReviewModelConfig
from unmask.reviewers.schemas import FindingReview, FollowupRequest

__all__ = [
    "build_reviewer", "review_finding", "adjudicate", "review_assessment",
    "build_batch_reviewer", "review_assessment_batched",
    "SINGLE_REVIEW_THRESHOLD", "BATCH_SIZE", "MAX_BATCH_TURNS",
    "ReviewConfigError", "ReviewModelConfig",
    "FindingReview", "FollowupRequest",
]

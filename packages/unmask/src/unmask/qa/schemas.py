"""Typed rule-tuning suggestions (post-report QA).

Engineering feedback, NOT part of the target's disposition: when a rule fires too
permissively or too noisily, propose a tweak — but every suggestion is advisory,
cites concrete findings, and must state the false-negative risk of acting on it.
Nothing here ever mutates rules, packs, or taxonomy.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

RuleTuningKind = Literal[
    "raise-threshold",
    "add-attenuator",
    "add-disproof",
    "split-rule",
    "merge-rule",
    "add-allowlist-pattern",
    "improve-evidence-requirement",
    "update-taxonomy-guidance",
    "needs-human-rule-review",
]


class RuleTuningSuggestion(BaseModel):
    kind: RuleTuningKind
    finding_ids: list[str] = Field(min_length=1,
                                   description="the concrete findings this is about (>=1 required)")
    rule_ids: list[str] = Field(default_factory=list)
    taxonomy_refs: list[str] = Field(default_factory=list)
    suggestion: str
    rationale: str
    evidence: list[str] = Field(default_factory=list)
    estimated_noise_reduction: str | None = None
    risk: str = Field(description="what could become a FALSE NEGATIVE if this is applied")

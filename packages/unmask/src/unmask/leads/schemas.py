"""Typed lead proposals.

A *lead* is a proposed investigation into RESIDUE — signal the deterministic passes left
with no verdict (a file that produced atoms but composed into no finding, a binary the
reveal/decompile triggers didn't open up). The model proposes WHERE to look and WHICH
known investigation to run; it never authors a verdict. Each lead's ``kind`` is a
constrained action the engine can execute deterministically (or, for ``human``, track as
an explicit open lead) — so a lead can only ever *add* coverage, never soften it.

Bounded/typed for the same reasons as the reviewer: malformed or over-eager model output
degrades to a tracked human lead, never a silent claim.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

# Constrained to actions the deterministic layer knows how to carry out (or explicitly
# hand to a human). The model picks a kind + target; it does not invent an action.
LeadKind = Literal[
    "transform",   # open the artifact up (deobfuscate/decompile/unpack) via the RE seam
    "dataflow",    # re-run intra-file taint on a file whose steps only co-occur
    "human",       # can't be acted on deterministically; a tracked open lead for a human
]


class Lead(BaseModel):
    kind: LeadKind
    target: str = Field(description="the residue path or artifact logical_path to investigate")
    rationale: str = Field(description="why this residue is worth a look (one sentence)")


class LeadBatch(BaseModel):
    """The proposer returns a bounded batch. An empty batch is a valid answer ('nothing
    here worth a lead') — that's how loop-until-dry terminates."""
    leads: list[Lead] = Field(default_factory=list)


# What executing a lead produced — recorded on its ledger work item + surfaced in the
# report's leads section. `resolution` is set by the deterministic layer, never the model.
LeadResolution = Literal[
    "finding",      # execution surfaced a real finding (residue was malicious)
    "cleared",      # executed, nothing found (residue explained/benign)
    "unactionable", # no provider/capability to execute; downgraded to a human lead
    "human",        # model asked for human review directly
    "error",        # execution failed; tracked as open
]

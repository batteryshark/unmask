"""Graph state and dependencies — unmask's domain extension of muster's spine.

muster owns the generic ``GraphState`` (run identity + counters) and ``GraphDeps``
(ledger + paths + resume/scratch). unmask subclasses both: state adds nothing yet;
deps add the MCD config, the discovered RE toolchain, an optional injected review
model, and the per-role ``model_for`` resolver. The graph itself is assembled in
``nodes.py`` with pydantic-graph's GraphBuilder.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from muster import GraphDeps, GraphState

from unmask.config import MCDConfig
from unmask.providers import ToolchainStatus


@dataclass(kw_only=True)
class MCDGraphState(GraphState):
    """unmask's transient run context — muster's identity/counter fields, unchanged."""


@dataclass(kw_only=True)
class MCDGraphDeps(GraphDeps):
    """Heavy objects live here, not in state. Adds the MCD config, the RE toolchain, and
    an optional injected pydantic-ai model for agentic review (tests pass TestModel;
    None resolves from UNMASK_REVIEW_* at review time)."""
    config: MCDConfig
    toolchain: ToolchainStatus
    review_model: Any = None

    def model_for(self, role: str):
        """Resolve the pydantic-ai model for a bounded model step's ROLE
        (reviewer/verifier/proposer/qa). An injected `review_model` overrides every role
        (tests, or a single-model run); otherwise `config.models[role]` → `config.model`
        → UNMASK_REVIEW_* env. This is the per-role speed/cost lever — cheap for
        proposer, strong for verifier — while endpoints/keys stay in env/harness."""
        if self.review_model is not None:
            return self.review_model
        from unmask.reviewers.config import ReviewModelConfig
        spec = (self.config.models or {}).get(role) or self.config.model
        return ReviewModelConfig.from_spec(spec).build_model()

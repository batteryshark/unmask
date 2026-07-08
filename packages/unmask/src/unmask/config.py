"""Run configuration.

Only the knobs the first build cut actually honours are wired; the rest are
placeholders kept aligned with docs/design.md so the CLI surface is stable as the
graph gains nodes.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Literal

SandboxMode = Literal["auto", "subprocess", "openshell", "none"]
NetworkMode = Literal["offline", "registry", "fetch-only", "dynamic"]
ToolProfile = Literal["static", "source", "binary", "full"]


@dataclass
class MCDConfig:
    storage_root: str = ".mcd"
    run_id: str = "auto"
    project_id: str = "auto"

    # Where the vendored parallax scanner (engine + mcd_lens) is resolved from.
    # "auto" -> $UNMASK_SCANNER_ROOT, else search upward for a parallax-goalpacks
    # checkout. Later this becomes a packaged, vendored copy.
    scanner_root: str = "auto"
    taxonomy_root: str = "auto"

    # Default posture: safe, offline, static. Nothing here executes target code.
    sandbox: SandboxMode = "auto"
    network: NetworkMode = "offline"
    tool_profile: ToolProfile = "static"

    # Agentic adjudication overlay (requires unmask[review]); off by default.
    review: bool = False
    # Adversarially verify review DOWNGRADES (refute/suppress/deescalate) with a quorum of
    # perspective-diverse skeptics before they stand — guards recall against a single
    # silent model opinion. Implies review; off by default (costs N model calls/downgrade).
    verify: bool = False
    # Default review-model spec ([provider:]model_id), and optional PER-ROLE overrides.
    # Roles: reviewer / verifier / proposer (leads) / qa. A role not in `models` falls
    # back to `model`, then to UNMASK_REVIEW_* env. This is where speed/cost tuning lives
    # — a cheap local model for high-volume steps (proposer), a strong one for the
    # low-volume/high-stakes ones (verifier). Provider endpoints/keys stay env/harness.
    model: str | None = None
    models: dict[str, str] = field(default_factory=dict)
    # Post-report rule-tuning QA: off | rules (advisory suggestions).
    post_report_qa: str = "off"
    # Adaptive investigation leads: the model proposes bounded follow-ups on residue
    # (signal the deterministic passes left with no verdict). Off by default; needs a
    # review model. Leads never author verdicts — they steer WHERE, rules judge WHAT.
    leads: bool = False
    # Human-in-the-loop: gate each remote fetch on a durable question. The first run
    # records the questions and finishes `needs_input` (no fetch); an orchestrator answers
    # and resumes. Never a blocking wait.
    confirm_fetch: bool = False

    tree_enabled: bool = True
    tree_max_depth: int = 4
    tree_max_entries: int = 2000

    max_iterations: int = 50

    def config_hash(self) -> str:
        """Stable hash of the config with volatile/secret-ish fields dropped."""
        stable = {k: v for k, v in asdict(self).items() if k not in {"run_id", "model", "models"}}
        blob = json.dumps(stable, sort_keys=True).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()[:12]

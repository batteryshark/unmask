"""Graph state and dependencies.

State is small and transient (run identity + counters); deps carry the heavy
objects (ledger, config, toolchain, optional review model). The graph itself is
assembled in `nodes.py` with pydantic-graph's GraphBuilder.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from unmask.config import MCDConfig
from unmask.ledger import LedgerStore
from unmask.providers import ToolchainStatus
from unmask.storage.paths import RunPaths


@dataclass
class MCDGraphState:
    """Small, transient run context (mirrors docs/design.md MCDGraphState)."""
    run_id: str
    project_id: str
    run_dir: Path
    db_path: Path
    target_path: Path
    iteration: int = 0
    max_iterations: int = 50


@dataclass
class MCDGraphDeps:
    """Heavy objects live here, not in state."""
    ledger: LedgerStore
    config: MCDConfig
    paths: RunPaths
    toolchain: ToolchainStatus
    # Optional injected pydantic-ai model for agentic review (tests pass TestModel;
    # None resolves from UNMASK_REVIEW_* at review time).
    review_model: Any = None
    scratch: dict[str, Any] = field(default_factory=dict)

"""Graph state, deps, and the internal phase runner."""

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
    scratch: dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphContext:
    state: MCDGraphState
    deps: MCDGraphDeps


@dataclass
class Done:
    """Terminal marker carrying the run result summary."""
    result: dict


class Node:
    """Base phase node. Subclasses implement run(ctx) -> Node | Done."""

    def run(self, ctx: GraphContext) -> "Node | Done":  # pragma: no cover - abstract
        raise NotImplementedError


def run_graph(start: Node, ctx: GraphContext) -> dict:
    """Drive nodes until Done. Records enter/exit graph_events; the ledger, not
    the node return value, is the durable record of what happened."""
    node: Node | Done = start
    while not isinstance(node, Done):
        name = type(node).__name__
        ctx.deps.ledger.event(ctx.state.run_id, name, "enter")
        try:
            nxt = node.run(ctx)
        except Exception as exc:
            ctx.deps.ledger.event(ctx.state.run_id, name, "error", {"error": repr(exc)})
            raise
        ctx.deps.ledger.event(ctx.state.run_id, name, "exit")
        ctx.state.iteration += 1
        if ctx.state.iteration > ctx.state.max_iterations:
            raise RuntimeError(f"graph exceeded max_iterations={ctx.state.max_iterations}")
        node = nxt
    return node.result

"""Phase graph.

The graph controls the workflow (discover -> scan -> compose -> gate -> report);
the ledger controls truth (coverage, resumability). The model never decides
completion — the CoverageGate does, from ledger state.

This first cut drives the nodes with a small internal runner (`run_graph`) using
the same node/context/ledger-oracle shape docs/design.md specifies for Pydantic
Graph. Swapping to pydantic-graph's builder API is mechanical and node-local.
"""

from __future__ import annotations

from unmask.graph.nodes import InitializeRun
from unmask.graph.runner import Done, GraphContext, MCDGraphDeps, MCDGraphState, run_graph

__all__ = ["Done", "GraphContext", "InitializeRun", "MCDGraphDeps", "MCDGraphState", "run_graph"]

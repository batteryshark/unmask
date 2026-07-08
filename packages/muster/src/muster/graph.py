"""Graph scaffolding — the generic phase-graph spine shared by every muster consumer.

muster does not own the graph *nodes* (pydantic-graph nodes are concrete-typed and
edge-inferred from their return annotations, so they necessarily reference a
consumer's own phases). What muster owns is the *mechanism* those nodes run on:

- ``GraphState`` / ``GraphDeps`` — the small transient run context and the heavy-object
  bag a consumer extends (both ``kw_only`` so a subclass can add required fields without
  the "non-default follows default" dataclass trap).
- ``atomic_write`` — crash-safe file replace, for reports and run.json.
- ``enter`` — phase-node entry: bump the iteration counter, record an ``enter`` event.
- ``ask`` — the DURABLE-QUESTION pattern: a node that can't decide records a
  content-addressed question and keeps going; the run finishes ``needs_input`` and an
  orchestrator answers + resumes. Never a blocking wait.
- ``WorkDispatcher`` — the work-queue drain mechanism: an ``operation -> handler``
  registry plus the lease/dispatch step. A consumer's ``ProcessWorkQueue`` node self-loops
  calling it; new operations plug in as handlers without touching the graph.

All the helpers are duck-typed on a pydantic-graph ``GraphRunContext`` whose ``state``
subclasses ``GraphState`` and ``deps`` subclasses ``GraphDeps``. See
docs/investigation-engine-seam.md.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from muster.ledger import Ledger, stable_key
from muster.paths import RunPaths


@dataclass(kw_only=True)
class GraphState:
    """Small, transient run context (identity + counters). Consumers subclass to add
    their own transient fields; the heavy objects live in ``GraphDeps``, not here."""
    run_id: str
    project_id: str
    run_dir: Path
    db_path: Path
    target_path: Path
    iteration: int = 0
    max_iterations: int = 50


@dataclass(kw_only=True)
class GraphDeps:
    """Heavy per-run objects (the ledger, the run-dir paths) plus generic run flags.
    Consumers subclass to add config, a toolchain, model handles, and a ``model_for``
    role resolver. ``scratch`` is inter-node scratch space; ``resume`` is True when the
    run is being re-driven from its ledger."""
    ledger: Ledger
    paths: RunPaths
    resume: bool = False
    scratch: dict[str, Any] = field(default_factory=dict)


def atomic_write(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` via a temp file + ``os.replace`` so a crash mid-write
    never leaves a half-written report."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def enter(ctx, name: str) -> None:
    """Phase-node entry: bump the iteration counter and record an ``enter`` event so the
    ledger's ``graph_events`` is a queryable trace of which phases ran, in order."""
    ctx.state.iteration += 1
    ctx.deps.ledger.event(ctx.state.run_id, name, "enter")


def ask(ctx, *, node: str, kind: str, prompt: str, options=None) -> str | None:
    """Ask a DURABLE question — never a blocking wait. Returns the answer if one was
    injected (a prior resume), else records the question as pending and returns None; the
    caller handles None by deferring that path. The run finishes ``needs_input`` while any
    question is unanswered, and an orchestrator answers + resumes. Idempotent: the id is
    content-addressed, so the same question maps to the same answer across re-drives."""
    qid = stable_key(prompt, kind, node)
    answer = ctx.deps.ledger.get_answer(ctx.state.run_id, qid)
    if answer is not None:
        return answer
    ctx.deps.ledger.ask_question(ctx.state.run_id, qid=qid, node=node, kind=kind,
                                 prompt=prompt, options=options)
    return None


WorkHandler = Callable[[Any, dict], None]


class WorkDispatcher:
    """The generic work-queue drain mechanism — a registry of ``operation -> handler``
    plus the lease/dispatch step. A consumer's ``ProcessWorkQueue`` node self-loops
    calling ``run_one`` (or leases itself and calls ``dispatch``); each handler drives its
    leased item to a terminal status and may enqueue follow-ups. An unknown operation is
    deferred with a note (never left leased — that would stall the loop), and a handler
    that raises fails its item rather than the run. New operations plug in as handlers
    without touching the graph."""

    def __init__(self, handlers: dict[str, WorkHandler] | None = None):
        self._handlers: dict[str, WorkHandler] = dict(handlers or {})

    def register(self, operation: str, handler: WorkHandler) -> "WorkDispatcher":
        self._handlers[operation] = handler
        return self

    def dispatch(self, ctx, item: dict) -> None:
        """Route one leased work item to its handler."""
        op = item.get("operation")
        handler = self._handlers.get(op)
        try:
            if handler is not None:
                handler(ctx, item)
            else:
                ctx.deps.ledger.set_work_status(item["id"], "deferred",
                    result={"note": f"No queue handler for operation {op!r}."})
        except Exception as exc:  # a handler bug must not stall the loop
            ctx.deps.ledger.set_work_status(item["id"], "failed", error=f"{type(exc).__name__}: {exc}")
            ctx.deps.ledger.event(ctx.state.run_id, "ProcessWorkQueue", "error",
                                  {"operation": op, "error": repr(exc)})

    def run_one(self, ctx) -> dict | None:
        """Lease the next actionable item and dispatch it. Returns the processed item, or
        None if the queue is drained."""
        item = ctx.deps.ledger.lease_next_actionable(ctx.state.run_id)
        if item is None:
            return None
        item = dict(item)
        self.dispatch(ctx, item)
        return item

"""muster.graph — the generic scaffolding + patterns, tested standalone."""

from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from muster import (
    GraphDeps, GraphState, Ledger, RunPaths, WorkDispatcher,
    ask, atomic_write, enter, stable_key,
)


@pytest.fixture
def ctx(tmp_path):
    """A minimal duck-typed GraphRunContext: the helpers only touch state.run_id/
    iteration and deps.ledger."""
    lg = Ledger(tmp_path / "run.db")
    lg.create_run(run_id="r1", project_id="p1", target_path="/t", target_root="/t",
                  storage_root=str(tmp_path), run_dir=str(tmp_path), config_json="{}")
    c = SimpleNamespace(state=SimpleNamespace(run_id="r1", iteration=0),
                        deps=SimpleNamespace(ledger=lg))
    yield c
    lg.close()


def test_atomic_write_leaves_no_temp(tmp_path):
    p = tmp_path / "out.txt"
    atomic_write(p, "hello")
    assert p.read_text() == "hello"
    assert not (tmp_path / "out.txt.tmp").exists()          # temp renamed away


def test_enter_bumps_iteration_and_records_event(ctx):
    enter(ctx, "Phase1")
    enter(ctx, "Phase2")
    assert ctx.state.iteration == 2
    events = ctx.deps.ledger.conn.execute(
        "select node, event from graph_events where run_id='r1' order by created_at").fetchall()
    assert [e["node"] for e in events] == ["Phase1", "Phase2"]
    assert all(e["event"] == "enter" for e in events)


def test_ask_is_durable_not_blocking(ctx):
    # unanswered → None (caller defers), and the question is now pending
    assert ask(ctx, node="N", kind="consent", prompt="go?", options=["y", "n"]) is None
    assert ctx.deps.ledger.count_pending_questions("r1") == 1
    # inject the answer → the same content-addressed question resolves on re-ask
    ctx.deps.ledger.record_answer("r1", stable_key("go?", "consent", "N"), "y")
    assert ask(ctx, node="N", kind="consent", prompt="go?") == "y"


def _handler_done(seen):
    def h(c, item):
        seen.append(item["target"])
        c.deps.ledger.set_work_status(item["id"], "done")
    return h


def test_dispatcher_run_one_leases_and_dispatches(ctx):
    seen: list[str] = []
    disp = WorkDispatcher().register("probe", _handler_done(seen))
    ctx.deps.ledger.enqueue(run_id="r1", key=stable_key("x"), target="x",
                            operation="probe", category="c", title="t")
    item = disp.run_one(ctx)
    assert item["target"] == "x" and seen == ["x"]
    assert disp.run_one(ctx) is None                        # queue drained


def test_dispatcher_unknown_op_is_deferred_never_stalls(ctx):
    ctx.deps.ledger.enqueue(run_id="r1", key=stable_key("y"), target="y",
                            operation="mystery", category="c", title="t")
    WorkDispatcher().run_one(ctx)                           # no handler registered
    assert ctx.deps.ledger.count_work_items("r1", operation="mystery", status="deferred") == 1


def test_dispatcher_handler_exception_fails_item_not_loop(ctx):
    def boom(c, item):
        raise RuntimeError("kaboom")
    ctx.deps.ledger.enqueue(run_id="r1", key=stable_key("z"), target="z",
                            operation="boom", category="c", title="t")
    WorkDispatcher({"boom": boom}).run_one(ctx)             # exception isolated to the item
    assert ctx.deps.ledger.count_work_items("r1", operation="boom", status="failed") == 1


def test_dispatcher_node_label_attributes_the_error_event(ctx):
    """A consumer passes its drain-node name so a handler failure is attributed to the node
    that actually ran, not a hardcoded consumer name leaked into generic muster."""
    def boom(c, item):
        raise RuntimeError("x")
    ctx.deps.ledger.enqueue(run_id="r1", key=stable_key("z"), target="z",
                            operation="boom", category="c", title="t")
    WorkDispatcher({"boom": boom}, node_label="MyDrainNode").run_one(ctx)
    ev = ctx.deps.ledger.conn.execute(
        "select node from graph_events where run_id='r1' and event='error'").fetchone()
    assert ev["node"] == "MyDrainNode"


def test_bases_are_kw_only_so_a_subclass_can_add_required_fields(tmp_path):
    """GraphState/GraphDeps are kw_only, so a consumer subclass can add a REQUIRED field
    without the 'non-default argument follows default argument' dataclass trap."""
    @dataclass(kw_only=True)
    class MyDeps(GraphDeps):
        config: str                                         # required, after base defaults

    lg = Ledger(tmp_path / "r.db")
    paths = RunPaths(storage_root=tmp_path, project_id="p", run_id="r", run_dir=tmp_path)
    d = MyDeps(ledger=lg, paths=paths, config="strict")
    assert d.config == "strict" and d.resume is False and d.scratch == {}
    lg.close()

    @dataclass(kw_only=True)
    class MyState(GraphState):
        depth: int

    s = MyState(run_id="r", project_id="p", run_dir=tmp_path, db_path=tmp_path / "x",
                target_path=tmp_path, depth=3)
    assert s.depth == 3 and s.iteration == 0

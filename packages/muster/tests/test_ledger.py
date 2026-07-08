"""muster.Ledger — the generic spine, tested standalone (no consumer domain)."""

from __future__ import annotations

import pytest

from muster import Ledger, SCHEMA_VERSION, new_id, stable_key


@pytest.fixture
def ledger(tmp_path):
    lg = Ledger(tmp_path / "run.db")
    lg.create_run(run_id="r1", project_id="p1", target_path="/t", target_root="/t",
                  storage_root=str(tmp_path), run_dir=str(tmp_path), config_json="{}")
    yield lg
    lg.close()


def test_new_id_and_stable_key():
    assert new_id("wi").startswith("wi-")
    assert new_id("wi") != new_id("wi")                     # unique per call
    k = stable_key("a", "b")
    assert k == stable_key("a", "b")                        # content-addressed, deterministic
    assert stable_key("a", "b") != stable_key("b", "a")    # order is part of the content
    assert len(k) == 24


def test_bare_ledger_has_spine_only(tmp_path):
    lg = Ledger(tmp_path / "c.db")
    tables = {r[0] for r in lg.conn.execute(
        "select name from sqlite_master where type='table'").fetchall()}
    assert {"runs", "artifacts", "work_items", "graph_events", "reports",
            "questions", "answers", "meta"} <= tables
    assert "observations" not in tables and "findings" not in tables   # no domain leakage
    assert lg.conn.execute(
        "select value from meta where key='schema_version'").fetchone()[0] == SCHEMA_VERSION
    lg.close()


def test_run_lifecycle(ledger):
    row = ledger.get_run("r1")
    assert row["status"] == "running" and row["project_id"] == "p1"
    ledger.finish_run("r1", "completed", coverage={"x": 1}, summary={"y": 2})
    row = ledger.get_run("r1")
    assert row["status"] == "completed" and row["completed_at"] is not None


def test_enqueue_dedup_by_stable_key(ledger):
    k = stable_key("a", "inventory")
    a = ledger.enqueue(run_id="r1", key=k, target="a", operation="inventory",
                       category="disc", title="t")
    b = ledger.enqueue(run_id="r1", key=k, target="a", operation="inventory",
                       category="disc", title="t")
    assert a == b                                           # same content → same row
    assert ledger.count_work_items("r1") == 1


def test_lease_priority_and_drain(ledger):
    ledger.enqueue(run_id="r1", key=stable_key("lo"), target="lo", operation="op",
                   category="c", title="lo", priority=10)
    ledger.enqueue(run_id="r1", key=stable_key("hi"), target="hi", operation="op",
                   category="c", title="hi", priority=99)
    first = ledger.lease_next_actionable("r1")
    assert first["target"] == "hi" and first["status"] == "leased"   # highest priority first
    ledger.set_work_status(first["id"], "done")
    second = ledger.lease_next_actionable("r1")
    assert second["target"] == "lo"
    ledger.set_work_status(second["id"], "done")
    assert ledger.lease_next_actionable("r1") is None      # drained
    assert ledger.actionable_count("r1") == 0


def test_status_counts_and_coverage(ledger):
    for i, st in enumerate(["done", "done", "blocked", "failed"]):
        wid = ledger.enqueue(run_id="r1", key=stable_key(f"w{i}"), target=f"w{i}",
                             operation="op", category="c", title="t")
        ledger.set_work_status(wid, st)
    cov = ledger.coverage("r1")
    assert cov["workItemsTotal"] == 4 and cov["done"] == 2
    assert cov["blocked"] == 1 and cov["failed"] == 1


def test_count_work_items_filters_by_operation_and_status(ledger):
    b = ledger.enqueue(run_id="r1", key=stable_key("bin"), target="bin",
                       operation="scan-binary", category="c", title="t")
    ledger.set_work_status(b, "blocked")
    f = ledger.enqueue(run_id="r1", key=stable_key("fetch"), target="u",
                       operation="fetch", category="c", title="t")
    ledger.set_work_status(f, "blocked")
    # both 'blocked' but different operations — the filter separates a binary blind spot
    # from a network-blocked fetch (the bug the filtered count was added to fix).
    assert ledger.count_work_items("r1", operation="scan-binary", status="blocked") == 1
    assert ledger.count_work_items("r1", operation="fetch", status="blocked") == 1
    assert ledger.count_work_items("r1", status="blocked") == 2


def test_questions_and_answers(ledger):
    qid = stable_key("go?", "consent", "N")
    ledger.ask_question("r1", qid=qid, node="N", kind="consent", prompt="go?",
                        options=["y", "n"])
    ledger.ask_question("r1", qid=qid, node="N", kind="consent", prompt="go?")   # idempotent
    assert ledger.count_pending_questions("r1") == 1
    pend = ledger.pending_questions("r1")
    assert pend[0]["id"] == qid and pend[0]["options"] == ["y", "n"]
    ledger.record_answer("r1", qid, "y")
    assert ledger.get_answer("r1", qid) == "y"
    assert ledger.count_pending_questions("r1") == 0       # answered → no longer pending


def test_reset_run_derived_keeps_run_and_answers(ledger):
    ledger.add_artifact(run_id="r1", kind="k", path="/p", logical_path="p", origin="inventory")
    ledger.enqueue(run_id="r1", key=stable_key("w"), target="w", operation="op",
                   category="c", title="t")
    qid = stable_key("q")
    ledger.ask_question("r1", qid=qid, node="N", kind="k", prompt="q")
    ledger.record_answer("r1", qid, "yes")
    ledger.reset_run_derived("r1")
    assert ledger.count_artifacts("r1") == 0
    assert ledger.count_work_items("r1") == 0
    assert ledger.count_pending_questions("r1") == 0       # questions are re-asked on re-drive
    assert ledger.get_run("r1") is not None                # the run row survives
    assert ledger.get_answer("r1", qid) == "yes"           # answers survive the reset


def test_extra_schema_and_reset_tables_registration(tmp_path):
    """A consumer registers a domain table + its resume-reset via the constructor —
    the option-B composition seam that keeps muster ignorant of the domain."""
    class DomainLedger(Ledger):
        def __init__(self, db_path):
            super().__init__(
                db_path,
                extra_schema="create table if not exists facts "
                             "(id text primary key, run_id text, v text);",
                reset_tables=("facts",))

    lg = DomainLedger(tmp_path / "d.db")
    lg.create_run(run_id="r", project_id="p", target_path="/t", target_root="/t",
                  storage_root=str(tmp_path), run_dir=str(tmp_path), config_json="{}")
    lg.conn.execute("insert into facts (id, run_id, v) values ('f1','r','x')")
    lg.conn.commit()
    assert lg.conn.execute("select count(*) from facts").fetchone()[0] == 1
    lg.reset_run_derived("r")
    assert lg.conn.execute("select count(*) from facts").fetchone()[0] == 0   # domain wiped
    lg.close()


def test_context_manager_closes(tmp_path):
    import sqlite3
    with Ledger(tmp_path / "cm.db") as lg:
        lg.create_run(run_id="r", project_id="p", target_path="/t", target_root="/t",
                      storage_root=str(tmp_path), run_dir=str(tmp_path), config_json="{}")
    with pytest.raises(sqlite3.ProgrammingError):
        lg.conn.execute("select 1")                        # connection closed on exit

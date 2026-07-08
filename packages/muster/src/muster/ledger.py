"""Ledger: the per-run SQLite spine — muster's durable coverage/resume oracle.

Every graph node reads ledger state on entry and records events/rows on exit;
completion is gated on ledger coverage, not on model output. This class owns the
GENERIC spine (runs, artifacts, the work queue, graph events, reports, and the
durable question/answer channel). A consumer registers its DOMAIN tables and the
tables to wipe on resume through the constructor:

    class MyStore(Ledger):
        def __init__(self, db_path):
            super().__init__(db_path,
                             extra_schema=MY_DOMAIN_SCHEMA_SQL,
                             reset_tables=("observations", "findings"))
            ...  # add domain record/count methods

muster never imports the consumer; the consumer subclasses (registration by
composition) so existing call sites keep using one store object. See
docs/investigation-engine-seam.md.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "0.1.0"
_CORE_SCHEMA_PATH = Path(__file__).with_name("schema.sql")
# Read once at import: the spine schema is a small data file, but a Ledger is constructed
# per run (and once per run by a project-wide rollup), so don't re-read it on every open.
_CORE_SCHEMA = _CORE_SCHEMA_PATH.read_text(encoding="utf-8")

# Spine tables a re-drive regenerates. Domain derived tables are appended by the
# consumer via reset_tables; the run row itself is always kept, and answers survive
# (they are injected before reset so a resumed run's re-asked question finds them).
_CORE_RESET_TABLES = ("artifacts", "work_items", "graph_events", "reports", "questions")


def utcnow() -> str:
    """UTC timestamp in ISO-8601 — the ledger's created_at/updated_at format. Public so a
    consumer's LedgerStore subclass can timestamp its domain rows consistently with the
    spine (part of the subclassing contract, not a private reach-in)."""
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def stable_key(*parts: str) -> str:
    """Content-derived work-item key; never derived from list order."""
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:24]


class Ledger:
    def __init__(self, db_path: str | Path, *, extra_schema: str = "",
                 reset_tables: Iterable[str] = ()):
        self.db_path = str(db_path)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        # A consumer's domain schema (applied after the core spine) and the domain
        # tables to wipe on resume, on top of the spine's own derived tables.
        self._extra_schema = extra_schema
        self._domain_reset_tables = tuple(reset_tables)
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.executescript(_CORE_SCHEMA)
        if self._extra_schema:
            self.conn.executescript(self._extra_schema)
        self.conn.execute(
            "insert or ignore into meta(key, value) values('schema_version', ?)",
            (SCHEMA_VERSION,),
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Ledger":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # --- runs -------------------------------------------------------------
    def create_run(self, *, run_id, project_id, target_path, target_root,
                   storage_root, run_dir, config_json) -> None:
        now = utcnow()
        self.conn.execute(
            """insert or replace into runs
               (id, project_id, target_path, target_root, storage_root, run_dir,
                status, created_at, updated_at, config_json)
               values (?,?,?,?,?,?,?,?,?,?)""",
            (run_id, project_id, str(target_path), str(target_root),
             str(storage_root), str(run_dir), "running", now, now, config_json),
        )
        self.conn.commit()

    def finish_run(self, run_id: str, status: str, *, coverage: dict | None = None,
                   summary: dict | None = None, error: str | None = None) -> None:
        now = utcnow()
        self.conn.execute(
            """update runs set status=?, updated_at=?, completed_at=?,
                              coverage_json=?, summary_json=?, error=? where id=?""",
            (status, now, now,
             json.dumps(coverage) if coverage is not None else None,
             json.dumps(summary) if summary is not None else None,
             error, run_id),
        )
        self.conn.commit()

    def get_run(self, run_id: str) -> sqlite3.Row | None:
        cur = self.conn.execute("select * from runs where id=?", (run_id,))
        return cur.fetchone()

    # --- artifacts --------------------------------------------------------
    def add_artifact(self, *, run_id, kind, path, logical_path, origin,
                     sha256=None, size_bytes=None, language=None,
                     media_type=None, metadata: dict | None = None) -> str:
        aid = new_id("art")
        self.conn.execute(
            """insert into artifacts
               (id, run_id, kind, path, logical_path, sha256, size_bytes,
                media_type, language, origin, metadata_json, created_at)
               values (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (aid, run_id, kind, str(path), logical_path, sha256, size_bytes,
             media_type, language, origin, json.dumps(metadata or {}), utcnow()),
        )
        self.conn.commit()
        return aid

    def count_artifacts(self, run_id: str, kind: str | None = None) -> int:
        if kind is None:
            cur = self.conn.execute("select count(*) c from artifacts where run_id=?", (run_id,))
        else:
            cur = self.conn.execute(
                "select count(*) c from artifacts where run_id=? and kind=?", (run_id, kind))
        return cur.fetchone()["c"]

    # --- work items -------------------------------------------------------
    def enqueue(self, *, run_id, key, target, operation, category, title,
                priority=100, depends_on=None, payload=None) -> str:
        now = utcnow()
        wid = new_id("wi")
        cur = self.conn.execute(
            """insert or ignore into work_items
               (id, run_id, stable_key, target, operation, category, title,
                status, priority, depends_on_json, payload_json, created_at, updated_at)
               values (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (wid, run_id, key, target, operation, category, title, "queued",
             priority, json.dumps(depends_on or []), json.dumps(payload or {}), now, now),
        )
        self.conn.commit()
        if cur.rowcount == 0:  # already present (stable key dedup)
            row = self.conn.execute(
                "select id from work_items where run_id=? and stable_key=?",
                (run_id, key)).fetchone()
            return row["id"]
        return wid

    def set_work_status(self, wid: str, status: str, *, result: dict | None = None,
                        error: str | None = None) -> None:
        now = utcnow()
        terminal = status in {"done", "failed", "needs_review", "deferred", "blocked"}
        self.conn.execute(
            """update work_items set status=?, updated_at=?, terminal_at=?,
                                     result_json=?, error=? where id=?""",
            (status, now, now if terminal else None,
             json.dumps(result) if result is not None else None, error, wid),
        )
        self.conn.commit()

    def work_status_counts(self, run_id: str) -> dict[str, int]:
        cur = self.conn.execute(
            "select status, count(*) c from work_items where run_id=? group by status", (run_id,))
        return {r["status"]: r["c"] for r in cur.fetchall()}

    def count_work_items(self, run_id: str, *, operation: str | None = None,
                         status: str | None = None) -> int:
        """Count work items, optionally filtered by operation and/or status. Lets a
        report count one operation's blind spots without conflating them with other
        items that share a status (e.g. binaries vs network-blocked fetches, both
        'blocked')."""
        sql = "select count(*) c from work_items where run_id=?"
        params: list = [run_id]
        if operation is not None:
            sql += " and operation=?"
            params.append(operation)
        if status is not None:
            sql += " and status=?"
            params.append(status)
        return self.conn.execute(sql, params).fetchone()["c"]

    def actionable_count(self, run_id: str) -> int:
        cur = self.conn.execute(
            "select count(*) c from work_items where run_id=? and status in ('queued','leased')",
            (run_id,))
        return cur.fetchone()["c"]

    def lease_next_actionable(self, run_id: str):
        """Claim the highest-priority queued work item (mark it `leased`) and return its
        row, or None if the queue is drained. The ProcessWorkQueue loop's lease step —
        a handler must then drive it to a terminal status."""
        row = self.conn.execute(
            "select * from work_items where run_id=? and status='queued' "
            "order by priority desc, created_at asc limit 1", (run_id,)).fetchone()
        if row is None:
            return None
        ts = utcnow()
        self.conn.execute("update work_items set status='leased', updated_at=? where id=?",
                          (ts, row["id"]))
        self.conn.commit()
        # Return the post-lease view (status='leased') so the caller sees the state it just
        # claimed — built in memory from the row already fetched, no second query. Nothing
        # reads the pre-lease snapshot; the sole caller re-wraps this in a dict.
        leased = dict(row)
        leased["status"] = "leased"
        leased["updated_at"] = ts
        return leased

    # --- resume (derived-state reset) ------------------------------------
    def delete_run_rows(self, run_id: str, *tables: str) -> None:
        """Delete this run's rows from the named tables. Public so a consumer subclass can
        do targeted domain resets (e.g. re-record observations over a recomposed union).
        Table names are internal constants, never user input."""
        for table in tables:
            self.conn.execute(f"delete from {table} where run_id=?", (run_id,))
        self.conn.commit()

    def reset_run_derived(self, run_id: str) -> None:
        """Clear everything a re-drive regenerates, keeping the run row itself. Resume
        starts from a clean slate so nodes re-record without duplicating; anything
        worth reusing (fetched bytes, decompiled trees, injected ANSWERS) lives on disk
        or in the answers table, not in these. Wipes the spine's derived tables plus
        the consumer's registered domain tables."""
        self.delete_run_rows(run_id, *_CORE_RESET_TABLES, *self._domain_reset_tables)

    # --- questions / answers (durable human-in-the-loop) -----------------
    def ask_question(self, run_id: str, *, qid: str, node: str, kind: str, prompt: str,
                     options: list | None = None) -> str:
        """Record a pending question (idempotent by content-addressed id)."""
        self.conn.execute(
            "insert or ignore into questions (id, run_id, node, kind, prompt, options_json, created_at) "
            "values (?,?,?,?,?,?,?)",
            (qid, run_id, node, kind, prompt, json.dumps(options or []), utcnow()))
        self.conn.commit()
        return qid

    def record_answer(self, run_id: str, qid: str, answer: str) -> None:
        """Persist an answer (survives resume's reset so the re-asked question finds it)."""
        self.conn.execute(
            "insert or replace into answers (id, run_id, answer, answered_at) values (?,?,?,?)",
            (qid, run_id, str(answer), utcnow()))
        self.conn.commit()

    def get_answer(self, run_id: str, qid: str) -> str | None:
        row = self.conn.execute("select answer from answers where id=?", (qid,)).fetchone()
        return row["answer"] if row else None

    def pending_questions(self, run_id: str) -> list[dict]:
        """Questions asked this run that have no answer yet — what the orchestrator must
        resolve before the run can complete."""
        rows = self.conn.execute(
            "select q.id, q.node, q.kind, q.prompt, q.options_json from questions q "
            "left join answers a on a.id=q.id where q.run_id=? and a.id is null "
            "order by q.created_at", (run_id,)).fetchall()
        return [{"id": r["id"], "node": r["node"], "kind": r["kind"], "prompt": r["prompt"],
                 "options": json.loads(r["options_json"])} for r in rows]

    def count_pending_questions(self, run_id: str) -> int:
        return self.conn.execute(
            "select count(*) c from questions q left join answers a on a.id=q.id "
            "where q.run_id=? and a.id is null", (run_id,)).fetchone()["c"]

    # --- events / reports -------------------------------------------------
    def event(self, run_id: str, node: str, event: str, payload: dict | None = None) -> None:
        self.conn.execute(
            """insert into graph_events (id, run_id, node, event, payload_json, created_at)
               values (?,?,?,?,?,?)""",
            (new_id("evt"), run_id, node, event, json.dumps(payload or {}), utcnow()),
        )
        self.conn.commit()

    def add_report(self, run_id: str, fmt: str, path: str | Path) -> None:
        p = Path(path)
        digest = hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
        self.conn.execute(
            """insert into reports (id, run_id, format, path, sha256, created_at)
               values (?,?,?,?,?,?)""",
            (new_id("rep"), run_id, fmt, str(path), digest, utcnow()),
        )
        self.conn.commit()

    def coverage(self, run_id: str) -> dict:
        counts = self.work_status_counts(run_id)
        total = sum(counts.values())
        return {
            "workItemsTotal": total,
            "done": counts.get("done", 0),
            "failed": counts.get("failed", 0),
            "blocked": counts.get("blocked", 0),
            "needsReview": counts.get("needs_review", 0),
            "deferred": counts.get("deferred", 0),
            "queued": counts.get("queued", 0),
        }

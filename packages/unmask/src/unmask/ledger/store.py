"""LedgerStore: thin typed wrapper over the per-run SQLite database.

Every graph node reads ledger state on entry and records events/rows on exit.
Completion is gated on ledger coverage, not on model output.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "0.1.0"
_SCHEMA_PATH = Path(__file__).with_name("schema.sql")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def stable_key(*parts: str) -> str:
    """Content-derived work-item key; never derived from list order."""
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:24]


class LedgerStore:
    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.executescript(_SCHEMA_PATH.read_text(encoding="utf-8"))
        self.conn.execute(
            "insert or ignore into meta(key, value) values('schema_version', ?)",
            (SCHEMA_VERSION,),
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "LedgerStore":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # --- runs -------------------------------------------------------------
    def create_run(self, *, run_id, project_id, target_path, target_root,
                   storage_root, run_dir, config_json) -> None:
        now = _now()
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
        now = _now()
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
             media_type, language, origin, json.dumps(metadata or {}), _now()),
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
        now = _now()
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
        now = _now()
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
        self.conn.execute("update work_items set status='leased', updated_at=? where id=?",
                          (_now(), row["id"]))
        self.conn.commit()
        return row

    # --- observations / findings -----------------------------------------
    def add_observation(self, *, run_id, atom, confidence, method, rule_id=None,
                        artifact_id=None, location=None, evidence=None,
                        relationships=None, obs_id=None) -> str:
        oid = obs_id or new_id("obs")
        self.conn.execute(
            """insert or replace into observations
               (id, run_id, artifact_id, atom, confidence, method, rule_id,
                location_json, evidence_json, relationships_json, created_at)
               values (?,?,?,?,?,?,?,?,?,?,?)""",
            (oid, run_id, artifact_id, atom, confidence, method, rule_id,
             json.dumps(location or {}), json.dumps(evidence or {}),
             json.dumps(relationships or []), _now()),
        )
        self.conn.commit()
        return oid

    def add_finding(self, *, run_id, lens, composition, title, severity, confidence,
                    confidence_label=None, claim="", evidence=None, disproof=None,
                    verification=None, response=None, amplifiers=None,
                    attenuators=None, finding_id=None) -> str:
        fid = finding_id or new_id("finding")
        self.conn.execute(
            """insert or replace into findings
               (id, run_id, lens, composition, title, claim, severity, confidence,
                confidence_label, evidence_json, disproof_json, verification_json,
                response_json, amplifiers_json, attenuators_json, created_at)
               values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (fid, run_id, lens, composition, title, claim, severity, confidence,
             confidence_label, json.dumps(evidence or []), json.dumps(disproof or []),
             json.dumps(verification or []), json.dumps(response or {}),
             json.dumps(amplifiers) if amplifiers is not None else None,
             json.dumps(attenuators) if attenuators is not None else None, _now()),
        )
        self.conn.commit()
        return fid

    def count_findings(self, run_id: str) -> int:
        cur = self.conn.execute("select count(*) c from findings where run_id=?", (run_id,))
        return cur.fetchone()["c"]

    def reset_observations(self, run_id: str) -> None:
        """Drop this run's observations so the post-transform union can be re-recorded
        without stale rows (finding/observation ids are renumbered over the union)."""
        self.conn.execute("delete from observations where run_id=?", (run_id,))
        self.conn.commit()

    def reset_findings(self, run_id: str) -> None:
        self.conn.execute("delete from findings where run_id=?", (run_id,))
        self.conn.commit()

    def reset_run_derived(self, run_id: str) -> None:
        """Clear everything a re-drive regenerates, keeping the run row itself. Resume
        starts from a clean slate so nodes re-record without duplicating; anything
        worth reusing (fetched bytes, decompiled trees) lives on disk, not in these
        tables."""
        for table in ("artifacts", "observations", "findings", "work_items",
                      "graph_events", "judgments", "qa_suggestions", "reports"):
            self.conn.execute(f"delete from {table} where run_id=?", (run_id,))
        self.conn.commit()

    # --- judgments (agentic review) --------------------------------------
    def record_judgment(self, run_id: str, review, *, reviewer="agentic", model=None) -> str:
        """Persist a FindingReview as a durable judgment row."""
        jid = new_id("judg")
        self.conn.execute(
            """insert into judgments
               (id, run_id, finding_id, reviewer, model, verdict, reviewed_confidence,
                response_tier, excluded_from_disposition, justification, followups_json, created_at)
               values (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (jid, run_id, review.finding_id, reviewer, model, review.verdict,
             review.reviewed_confidence, review.response_tier,
             1 if review.excluded_from_disposition else 0, review.justification,
             json.dumps([f.model_dump() for f in review.followups]), _now()),
        )
        self.conn.commit()
        return jid

    def count_judgments(self, run_id: str) -> int:
        cur = self.conn.execute("select count(*) c from judgments where run_id=?", (run_id,))
        return cur.fetchone()["c"]

    # --- qa suggestions (advisory rule tuning) ---------------------------
    def record_qa_suggestion(self, run_id: str, suggestion) -> str:
        qid = new_id("qa")
        self.conn.execute(
            """insert into qa_suggestions
               (id, run_id, kind, finding_ids_json, rule_ids_json, suggestion, rationale,
                risk, estimated_noise_reduction, created_at)
               values (?,?,?,?,?,?,?,?,?,?)""",
            (qid, run_id, suggestion.kind, json.dumps(suggestion.finding_ids),
             json.dumps(suggestion.rule_ids), suggestion.suggestion, suggestion.rationale,
             suggestion.risk, suggestion.estimated_noise_reduction, _now()),
        )
        self.conn.commit()
        return qid

    def count_qa_suggestions(self, run_id: str) -> int:
        cur = self.conn.execute("select count(*) c from qa_suggestions where run_id=?", (run_id,))
        return cur.fetchone()["c"]

    # --- events / reports -------------------------------------------------
    def event(self, run_id: str, node: str, event: str, payload: dict | None = None) -> None:
        self.conn.execute(
            """insert into graph_events (id, run_id, node, event, payload_json, created_at)
               values (?,?,?,?,?,?)""",
            (new_id("evt"), run_id, node, event, json.dumps(payload or {}), _now()),
        )
        self.conn.commit()

    def add_report(self, run_id: str, fmt: str, path: str | Path) -> None:
        p = Path(path)
        digest = hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
        self.conn.execute(
            """insert into reports (id, run_id, format, path, sha256, created_at)
               values (?,?,?,?,?,?)""",
            (new_id("rep"), run_id, fmt, str(path), digest, _now()),
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

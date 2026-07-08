"""LedgerStore: the unmask DOMAIN ledger — muster's core spine plus MCD tables.

muster.Ledger owns the generic spine (runs, artifacts, the work queue, graph
events, reports, and the durable question/answer channel). LedgerStore registers
the malicious-code-detection domain by composition: it passes its domain schema
(observations / findings / judgments / qa_suggestions) and the domain tables to
wipe on resume to the core, then adds only the domain record/count/reset methods.

Callers still see one store object with all methods, so nothing outside this file
changed when the spine moved to muster.
"""

from __future__ import annotations

import json
from pathlib import Path

# Re-exported so existing call sites (nodes.py `from unmask.ledger.store import
# stable_key`, ledger/__init__ `SCHEMA_VERSION, new_id`) keep working after the
# spine moved to muster.
from muster.ledger import SCHEMA_VERSION, Ledger, new_id, stable_key, utcnow  # noqa: F401

_DOMAIN_SCHEMA_PATH = Path(__file__).with_name("schema.sql")
_DOMAIN_SCHEMA = _DOMAIN_SCHEMA_PATH.read_text(encoding="utf-8")  # read once at import
# Domain derived tables muster's reset_run_derived wipes on resume, on top of the
# spine's own (artifacts, work_items, graph_events, reports, questions).
_DOMAIN_RESET_TABLES = ("observations", "findings", "judgments", "qa_suggestions")


class LedgerStore(Ledger):
    def __init__(self, db_path: str | Path):
        super().__init__(
            db_path,
            extra_schema=_DOMAIN_SCHEMA,
            reset_tables=_DOMAIN_RESET_TABLES,
        )

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
             json.dumps(relationships or []), utcnow()),
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
             json.dumps(attenuators) if attenuators is not None else None, utcnow()),
        )
        self.conn.commit()
        return fid

    def count_findings(self, run_id: str) -> int:
        cur = self.conn.execute("select count(*) c from findings where run_id=?", (run_id,))
        return cur.fetchone()["c"]

    def reset_observations(self, run_id: str) -> None:
        """Drop this run's observations so the post-transform union can be re-recorded
        without stale rows (finding/observation ids are renumbered over the union)."""
        self.delete_run_rows(run_id, "observations")

    def reset_findings(self, run_id: str) -> None:
        self.delete_run_rows(run_id, "findings")

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
             json.dumps([f.model_dump() for f in review.followups]), utcnow()),
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
             suggestion.risk, suggestion.estimated_noise_reduction, utcnow()),
        )
        self.conn.commit()
        return qid

    def count_qa_suggestions(self, run_id: str) -> int:
        cur = self.conn.execute("select count(*) c from qa_suggestions where run_id=?", (run_id,))
        return cur.fetchone()["c"]

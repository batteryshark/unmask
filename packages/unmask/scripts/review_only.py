#!/usr/bin/env python3
"""Re-run ONLY the agentic review over an existing run's frozen findings.

A dev tool for iterating on review models. `unmask run --review` and `unmask resume`
both re-drive the whole graph (walk, transform, scan, compose) before they reach the
review — minutes of work — which makes A/B-testing review models painful. The scan is
deterministic and already persisted in the run's SQLite ledger, so this loads the
findings + observations straight from `run.db` and runs just the review against
whichever model your endpoint is serving. Swap the model on the server, re-run, done.

Usage:
    python scripts/review_only.py <run-dir-or-run.db> [max-findings]

The review model is env-driven (same vars as `unmask run --review`):
    UNMASK_REVIEW_MODEL     model id (default: auto-detected from the endpoint)
    UNMASK_REVIEW_BASE_URL  endpoint base url (default: http://127.0.0.1:1357)
    UNMASK_REVIEW_KIND      wire protocol: 'anthropic' or 'openai' (default: openai)
    UNMASK_REVIEW_API_KEY   api key (default: 'local')

Read-only: it opens run.db read-only and prints verdicts; it does not write to the run.
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import time
import urllib.request
from collections import Counter
from pathlib import Path

BASE = os.environ.get("UNMASK_REVIEW_BASE_URL", "http://127.0.0.1:1357")


def _resolve_db(arg: str) -> str:
    p = Path(arg)
    if p.is_dir():
        p = p / "run.db"
    if not p.is_file():
        sys.exit(f"review_only: no run.db at {p}")
    return str(p)


def _auto_model() -> str:
    with urllib.request.urlopen(BASE + "/v1/models", timeout=8) as r:
        return json.load(r)["data"][0]["id"]


def _j(s, default):
    try:
        return json.loads(s) if s else default
    except (ValueError, TypeError):
        return default


def main() -> int:
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    db = _resolve_db(sys.argv[1])
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else 0

    os.environ["UNMASK_REVIEW_MODEL"] = os.environ.get("UNMASK_REVIEW_MODEL") or _auto_model()
    os.environ.setdefault("UNMASK_REVIEW_BASE_URL", BASE)
    os.environ.setdefault("UNMASK_REVIEW_API_KEY", "local")

    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    findings = [{
        "id": r["id"], "severity": r["severity"], "confidence": r["confidence"],
        "title": r["title"], "claim": r["claim"], "composition": r["composition"],
        "disproofCriteria": _j(r["disproof_json"], []), "evidence": _j(r["evidence_json"], []),
    } for r in con.execute("select * from findings")]
    observations = [{
        "id": r["id"], "atom": r["atom"],
        "location": _j(r["location_json"], {}), "evidence": _j(r["evidence_json"], None),
    } for r in con.execute("select * from observations")]
    if limit:
        findings = findings[:limit]
    assessment = {"findings": findings, "observations": observations,
                  "disposition": {"recommendation": "review"}}

    from unmask.reviewers import review_assessment_batched
    from unmask.reviewers.config import ReviewModelConfig

    model = ReviewModelConfig.from_env().build_model()
    print(f"model = {os.environ['UNMASK_REVIEW_MODEL']}")
    print(f"findings = {len(findings)}  observations = {len(observations)}\n")

    t = time.time()
    reviews, adjudication = review_assessment_batched(assessment, model=model)
    dt = time.time() - t

    by_id = {f["id"]: f for f in findings}
    tally: Counter = Counter()
    for rv in reviews:
        f = by_id.get(rv.finding_id, {})
        tally[rv.verdict] += 1
        print(f"  [{rv.verdict:11}] {rv.finding_id:7} {f.get('composition', ''):14} "
              f"eng={f.get('severity', '')}/{f.get('confidence')} -> {rv.reviewed_confidence:.2f}  "
              f"{f.get('title', '')[:44]}")
        print(f"      {rv.justification[:160]}")
    print(f"\nreviewed {len(reviews)}/{len(findings)} in {dt:.1f}s   verdicts: {dict(tally)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

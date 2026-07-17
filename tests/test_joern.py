"""Focused contract test for the optional Rekit/Joern evidence provider."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from unmask.scanner.compose.common import _dataflow_status
from unmask.scanner.deep.joern import (
    RekitJoernProvider,
    _canonical_digest,
    _load_evidence,
    _profile_digest,
    apply_joern_result,
)
from unmask.scanner.observe.atoms import Observation
from unmask.scanner.observe.inventory import FileEntry, Inventory


def test_explicit_rekit_path_enriches_selected_finding(tmp_path):
    target = tmp_path / "pkg"
    target.mkdir()
    app = target / "app.py"
    helper = target / "helper.py"
    app.write_text("payload = fetch_it(url)\nexec(payload)\n")
    helper.write_text("def fetch_it(url):\n    return download(url)\n")
    inv = Inventory(root=str(target), files=[
        FileEntry(str(app), "app.py", "source", "python", size=app.stat().st_size),
        FileEntry(str(helper), "helper.py", "source", "python", size=helper.stat().st_size),
    ])
    observations = [
        Observation("NETW.HTTP", 0.8, "source-callee", "app.py", 1,
                    evidence="fetch_it", id="obs-1"),
        Observation("LOAD.EVAL", 0.8, "source-callee", "app.py", 2,
                    evidence="exec", id="obs-2"),
    ]
    findings = [{
        "id": "mcd-1",
        "composition": "BP-DROPPER",
        "claim": "Fetch and execution co-occur. Dataflow: not proven.",
        "evidence": ["obs-1", "obs-2"],
    }]
    commands = []

    def fake_runner(command: list[str], timeout: int):
        commands.append((command, timeout))
        staged = Path(command[3])
        output = Path(command[4])
        output.mkdir(parents=True)
        manifest_files = []
        for path in sorted(item for item in staged.rglob("*") if item.is_file()):
            data = path.read_bytes()
            manifest_files.append({
                "path": path.relative_to(staged).as_posix(),
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            })
        manifest = _canonical_digest({"files": manifest_files})
        (output / "cpg.bin").write_bytes(b"fake-cpg")
        (output / "raw-slice.json").write_text("{}")
        evidence = {
            "schemaVersion": 1,
            "producer": {
                "tool": "joern-slice", "joernVersion": "fixture",
                "revision": "fixture", "image": "fixture@sha256:" + "a" * 64,
                "runtime": "fake",
            },
            "target": {"manifestSha256": manifest},
            "analysis": {
                "mode": "behavior-flow", "language": "pythonsrc",
                "profile": "unmask-selected-behavior-flow-v1",
                "profileSha256": _profile_digest(), "proofDepth": "interprocedural-cpg",
                "sliceDepth": 12,
                "limits": {"timeoutSeconds": 30},
            },
            "coverage": {"unresolved": [], "excluded": [], "limitations": [
                "one run represents one frontend and does not establish cross-language flow"
            ]},
            "graph": {
                "nodes": [
                    {"id": "n1", "parentFile": "app.py", "parentMethod": "launch",
                     "lineNumber": 1, "code": "fetch_it(url)"},
                    {"id": "n2", "parentFile": "helper.py", "parentMethod": "launch",
                     "lineNumber": 2, "code": "exec(payload)"},
                ],
                "edges": [{"src": "n1", "dst": "n2", "label": "REACHING_DEF"}],
                "paths": [{"id": "p1", "nodes": ["n1", "n2"],
                           "sinkContext": "n2", "relation": "explicit-reaching-def"}],
                "findings": [{"id": "f1", "sourceKind": "network-fetch",
                              "sinkKind": "code-execution", "path": "p1"}],
            },
            "metrics": {"findings": 1},
        }
        (output / "evidence.json").write_text(json.dumps(evidence))
        return subprocess.CompletedProcess(command, 0, stdout='{"ok":true}', stderr="")

    result = RekitJoernProvider(
        dispatcher="fake-rekit", timeout=30, runner=fake_runner
    ).analyze(findings, observations, inv, str(tmp_path / "artifacts"))
    apply_joern_result(result, observations, inv)

    assert len(commands) == 1
    assert commands[0][0][:3] == ["fake-rekit", "run", "joern-slice"]
    assert commands[0][0].count("pythonsrc") == 1  # one frontend / one CPG
    assert result.summary["status"] == "completed"
    assert result.summary["explicitPaths"] == 1
    confidence, claim, *_ = _dataflow_status(inv, "app.py", {"dropper"}, 0.65, 0.9)
    assert confidence == 0.9
    assert "interprocedural Joern CPG" in claim
    assert observations[0].relationships[0]["evidenceArtifact"].endswith("evidence.json")
    with pytest.raises(ValueError, match="target manifest"):
        _load_evidence(
            tmp_path / "artifacts" / "pythonsrc" / "evidence.json",
            "pythonsrc",
            "0" * 64,
            30,
            12,
        )


def test_already_proven_finding_does_not_call_joern(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("exec(fetch(url))\n")
    inv = Inventory(root=str(tmp_path), files=[
        FileEntry(str(source), "app.py", "source", "python", size=source.stat().st_size)
    ])
    observations = [
        Observation("NETW.HTTP", 0.8, "source-callee", "app.py", 1,
                    evidence="fetch", id="obs-1")
    ]

    def must_not_run(_command, _timeout):
        raise AssertionError("Joern must run only for unresolved, selected flow questions")

    result = RekitJoernProvider(
        dispatcher="fake-rekit", runner=must_not_run
    ).analyze([{
        "id": "mcd-1", "composition": "BP-DROPPER",
        "claim": "Dataflow: PROVEN by native Tree-sitter taint.",
        "evidence": ["obs-1"],
    }], observations, inv, str(tmp_path / "artifacts"))

    assert result.summary["status"] == "not-selected"
    assert result.summary["frontends"] == []
    assert result.proofs == {}


def test_implicit_sink_slice_does_not_promote_confidence():
    inv = Inventory(root="/target", dataflow={
        "app.py": [{
            "kind": "dropper", "shape": "fetch -> exec",
            "sourceKind": "fetch", "sinkKind": "exec",
            "provider": "joern-slice", "frontend": "pythonsrc",
            "relation": "slice-selected-by-sink", "pathId": "p-implicit",
        }]
    })

    confidence, claim, _disproof, _amplifiers, attenuators = _dataflow_status(
        inv, "app.py", {"dropper"}, 0.65, 0.9
    )

    assert confidence == 0.65
    assert "confidence is not promoted" in claim
    assert any("implicit sink" in item.lower() for item in attenuators)


def test_unavailable_dispatcher_is_reported_without_losing_native_result(tmp_path):
    from unmask import MCDConfig, run_mcd

    fixture = Path(__file__).parent / "fixtures" / "proven-dataflow" / "unproven_decode.js"
    result = run_mcd(str(fixture), MCDConfig(
        storage_root=str(tmp_path / ".mcd"),
        joern_enabled=True,
        joern_dispatcher=str(tmp_path / "missing-rekit"),
        joern_timeout=5,
    ))
    report = json.loads(Path(result.report_paths["json"]).read_text())

    assert result.status == "completed"
    assert "BP-OBFEXEC" in report["summary"]["compositions"]
    assert report["deepStaticAnalysis"]["status"] == "unavailable"
    assert report["coverage"]["deepStaticAnalysis"]["status"] == "unavailable"
    obfexec = next(f for f in report["findings"] if f["composition"] == "BP-OBFEXEC")
    assert obfexec["confidence"] == 0.6  # broad/native judgment is preserved

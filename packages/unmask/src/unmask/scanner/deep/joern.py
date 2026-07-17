"""Focused Joern evidence through Rekit's public ``joern-slice`` dispatcher.

The native scanner remains the broad language surface and judgment layer. This
module receives its already-composed findings, selects unresolved flow questions,
runs at most one CPG per selected Joern frontend, and maps Rekit's versioned evidence
contract back into ``Inventory.dataflow`` and observation relationships.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Callable


PROFILE = Path(__file__).with_name("behavior-flow.json")
PROFILE_ID = "unmask-selected-behavior-flow-v1"
_MAX_FRONTENDS = 8
_MAX_INPUT_FILES = 10_000
_MAX_INPUT_BYTES = 512 * 1024 * 1024
_MAX_EVIDENCE_BYTES = 32 * 1024 * 1024
_IMMUTABLE_IMAGE = re.compile(r"^.+@sha256:[0-9a-f]{64}$")

# Unmask language -> Joern source frontend. Closely related source variants share
# one frontend/CPG; no evidence is joined across these frontend runs.
_FRONTEND_BY_LANGUAGE = {
    "python": "pythonsrc",
    "javascript": "jssrc",
    "typescript": "jssrc",
    "tsx": "jssrc",
    "c": "c",
    "cpp": "c",
    "objc": "c",
    "java": "javasrc",
    "csharp": "csharpsrc",
    "go": "golang",
    "kotlin": "kotlin",
    "php": "php",
    "ruby": "rubysrc",
    "rust": "rust",
    "swift": "swiftsrc",
}

_KINDS_BY_COMPOSITION = {
    "BP-DROPPER": {"dropper"},
    "BP-OBFEXEC": {"decode-exec"},
    "BP-CREDTHEFT": {"exfil"},
    "BP-EXFIL": {"exfil"},
    "BP-RANSOM": {"ransom"},
    "BP-WORM": {"propagation"},
    "BP-MITM": {"mitm"},
}

# Declarative profile ids -> the native proof kind consumed by compose.common.
_FLOW_MAP = {
    ("network-fetch", "code-execution"): ("dropper", "fetch", "exec", "fetch -> exec"),
    ("network-fetch", "file-write"): ("dropper", "fetch", "write", "fetch -> write"),
    ("decode", "code-execution"): ("decode-exec", "decode", "exec", "decode -> exec"),
    ("decode", "file-write"): ("dropper", "decode", "write", "decode -> write"),
    ("secret-read", "network-egress"): ("exfil", "secret", "egress", "secret read -> egress"),
    ("sensitive-read", "network-egress"): (
        "exfil", "sensitive", "egress", "sensitive read -> egress"
    ),
    ("path-enumeration", "encryption"): (
        "ransom", "pathset", "encrypt", "enumerated path -> encryption"
    ),
    ("path-enumeration", "file-write"): (
        "ransom", "pathset", "write", "enumerated path -> write"
    ),
    ("path-enumeration", "file-delete"): (
        "ransom", "pathset", "delete", "enumerated path -> delete"
    ),
    ("target-discovery", "network-egress"): (
        "propagation", "target", "egress", "discovered target -> network action"
    ),
    ("target-discovery", "code-execution"): (
        "propagation", "target", "exec", "discovered target -> command execution"
    ),
    ("target-discovery", "file-write"): (
        "propagation", "target", "write", "discovered target -> file staging"
    ),
    ("trust-disable", "network-egress"): (
        "mitm", "trust-disable", "egress", "trust disablement -> network operation"
    ),
}

_Runner = Callable[[list[str], int], subprocess.CompletedProcess[str]]


@dataclass
class DeepStaticResult:
    summary: dict
    proofs: dict[str, list[dict]] = field(default_factory=dict)
    relationships: dict[str, list[dict]] = field(default_factory=dict)
    artifacts: list[dict] = field(default_factory=list)


def _canonical_digest(value: object) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _profile_digest() -> str:
    return _canonical_digest(json.loads(PROFILE.read_text(encoding="utf-8")))


def _run_command(command: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command, capture_output=True, text=True, check=False, timeout=timeout
    )


def _needs_deep_evidence(finding: dict) -> bool:
    text = " ".join([
        str(finding.get("claim") or ""),
        *[str(x) for x in finding.get("amplifiers") or []],
        *[str(x) for x in finding.get("attenuators") or []],
    ]).lower()
    return "dataflow: not proven" in text or "proof depth: same-file co-occurrence" in text


def _triage(findings: list[dict], observations: list) -> dict:
    obs_by_id = {getattr(o, "id", None): o for o in observations if getattr(o, "id", None)}
    paths_by_kind: dict[str, set[str]] = {}
    obs_by_kind_path: dict[tuple[str, str], set[str]] = {}
    selected = []
    for finding in findings:
        composition = finding.get("composition") or finding.get("_composition")
        kinds = _KINDS_BY_COMPOSITION.get(composition)
        if not kinds or not _needs_deep_evidence(finding):
            continue
        cited = [obs_by_id.get(oid) for oid in finding.get("evidence") or []]
        cited = [o for o in cited if o is not None and getattr(o, "path", None)]
        if not cited:
            continue
        selected.append(finding.get("id"))
        for kind in kinds:
            for obs in cited:
                paths_by_kind.setdefault(kind, set()).add(obs.path)
                obs_by_kind_path.setdefault((kind, obs.path), set()).add(obs.id)
    return {
        "findingIds": [fid for fid in selected if fid],
        "pathsByKind": paths_by_kind,
        "observationsByKindPath": obs_by_kind_path,
    }


def _safe_stage_rel(logical: str, used: set[str]) -> str:
    normalized = str(logical or "source").replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        normalized = f"source-{hashlib.sha256(normalized.encode()).hexdigest()[:12]}"
    if normalized in used:
        stem = PurePosixPath(normalized)
        normalized = str(stem.with_name(
            f"{stem.stem}-{hashlib.sha256(logical.encode()).hexdigest()[:8]}{stem.suffix}"
        ))
    used.add(normalized)
    return normalized


def _stage_frontend(
    inv, frontend: str, destination: Path
) -> tuple[dict[str, str], list[dict], str]:
    entries = [
        f for f in getattr(inv, "files", [])
        if getattr(f, "kind", None) == "source"
        and _FRONTEND_BY_LANGUAGE.get(getattr(f, "language", None)) == frontend
    ]
    if len(entries) > _MAX_INPUT_FILES:
        raise ValueError(f"frontend exceeds {_MAX_INPUT_FILES} source files")
    total = 0
    source_map: dict[str, str] = {}
    excluded: list[dict] = []
    manifest_entries: list[dict] = []
    used: set[str] = set()
    for entry in entries:
        source = Path(entry.path)
        if source.is_symlink() or not source.is_file():
            excluded.append({"path": entry.rel, "reason": "missing-or-symlink"})
            continue
        remaining = _MAX_INPUT_BYTES - total
        with source.open("rb") as handle:
            data = handle.read(remaining + 1)
        if len(data) > remaining:
            raise ValueError(f"frontend exceeds {_MAX_INPUT_BYTES} input bytes")
        staged_rel = _safe_stage_rel(entry.rel, used)
        staged = destination / staged_rel
        staged.parent.mkdir(parents=True, exist_ok=True)
        staged.write_bytes(data)
        staged.chmod(0o444)
        source_map[staged_rel] = entry.rel
        total += len(data)
        manifest_entries.append({
            "path": staged_rel,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        })
    if not source_map:
        raise ValueError("frontend has no readable regular source files")
    manifest_entries.sort(key=lambda item: item["path"])
    return source_map, excluded, _canonical_digest({"files": manifest_entries})


def _logical_path(raw: object, source_map: dict[str, str]) -> str | None:
    value = str(raw or "").replace("\\", "/")
    if value.startswith("/input/"):
        value = value[len("/input/"):]
    elif value.startswith("input/"):
        value = value[len("input/"):]
    if value in source_map:
        return source_map[value]
    matches = [logical for staged, logical in source_map.items()
               if value.endswith("/" + staged) or value == staged]
    return matches[0] if len(set(matches)) == 1 else None


def _load_evidence(
    path: Path, frontend: str, manifest: str, timeout: int, slice_depth: int
) -> dict:
    if not path.is_file() or path.stat().st_size > _MAX_EVIDENCE_BYTES:
        raise ValueError("Joern evidence artifact is missing or exceeds the evidence size bound")
    evidence = json.loads(path.read_text(encoding="utf-8"))
    required = {"schemaVersion", "producer", "target", "analysis", "coverage", "graph", "metrics"}
    if not isinstance(evidence, dict) or evidence.get("schemaVersion") != 1 \
            or not required.issubset(evidence):
        raise ValueError("Joern evidence does not satisfy the Rekit evidence v1 contract")
    graph = evidence.get("graph") or {}
    if any(not isinstance(graph.get(key), list) for key in ("nodes", "edges", "paths", "findings")):
        raise ValueError("Joern evidence graph is incomplete")
    analysis = evidence.get("analysis") or {}
    if analysis.get("language") != frontend or analysis.get("mode") != "behavior-flow":
        raise ValueError("Joern evidence frontend or mode does not match the request")
    if analysis.get("profile") != PROFILE_ID or analysis.get("profileSha256") != _profile_digest():
        raise ValueError("Joern evidence was not produced with Unmask's selected behavior profile")
    producer = evidence.get("producer") or {}
    if producer.get("tool") != "joern-slice":
        raise ValueError("Joern evidence producer is not Rekit's joern-slice")
    if not _IMMUTABLE_IMAGE.fullmatch(str(producer.get("image") or "")):
        raise ValueError("Joern evidence does not identify an immutable image digest")
    if (evidence.get("target") or {}).get("manifestSha256") != manifest:
        raise ValueError("Joern evidence target manifest does not match staged sources")
    if analysis.get("sliceDepth") != slice_depth:
        raise ValueError("Joern evidence does not preserve the requested slice depth")
    limits = analysis.get("limits")
    if not isinstance(limits, dict) or limits.get("timeoutSeconds") != timeout:
        raise ValueError("Joern evidence does not preserve the requested resource budget")
    if analysis.get("proofDepth") != "interprocedural-cpg":
        raise ValueError("Joern evidence has an unexpected proof depth")
    relations = {
        item.get("relation") for item in graph["paths"] if isinstance(item, dict)
    }
    if not relations <= {"explicit-reaching-def", "slice-selected-by-sink"}:
        raise ValueError("Joern evidence contains an unknown path relation")
    return evidence


def _location(node: dict | None, source_map: dict[str, str]) -> dict | None:
    if not node:
        return None
    path = _logical_path(node.get("parentFile"), source_map)
    if not path:
        return None
    return {
        "path": path,
        "line": node.get("lineNumber"),
        "column": node.get("columnNumber"),
        "method": node.get("parentMethod"),
        "code": node.get("code"),
    }


def _map_evidence(evidence: dict, frontend: str, source_map: dict[str, str],
                  triage: dict, evidence_path: Path) -> tuple[dict, dict, int, int]:
    graph = evidence["graph"]
    nodes = {node.get("id"): node for node in graph["nodes"] if isinstance(node, dict)}
    paths = {path.get("id"): path for path in graph["paths"] if isinstance(path, dict)}
    proofs: dict[str, list[dict]] = {}
    relationships: dict[str, list[dict]] = {}
    explicit = implicit = 0
    for finding in graph["findings"]:
        if not isinstance(finding, dict):
            continue
        mapped = _FLOW_MAP.get((finding.get("sourceKind"), finding.get("sinkKind")))
        if not mapped:
            continue
        kind, source_kind, sink_kind, shape = mapped
        candidate_paths = triage["pathsByKind"].get(kind, set())
        path = paths.get(finding.get("path"))
        if not path or not candidate_paths:
            continue
        path_nodes = [nodes.get(identifier) for identifier in path.get("nodes") or []]
        logical_paths = {
            logical for logical in (
                _logical_path(node.get("parentFile"), source_map)
                for node in path_nodes if node
            ) if logical
        }
        selected_paths = sorted(candidate_paths & logical_paths)
        if not selected_paths:
            continue
        relation = path.get("relation") or "slice-selected-by-sink"
        source = _location(path_nodes[0] if path_nodes else None, source_map)
        sink_node = nodes.get(path.get("sinkContext"))
        if relation == "explicit-reaching-def" and sink_node is None and path_nodes:
            sink_node = path_nodes[-1]
        sink = _location(sink_node, source_map)
        producer = evidence.get("producer") or {}
        provenance = {
            "provider": "joern-slice",
            "proofDepth": "interprocedural-cpg",
            "frontend": frontend,
            "relation": relation,
            "pathId": path.get("id"),
            "source": source,
            "sink": sink,
            "crossFile": len(logical_paths) > 1,
            "evidenceArtifact": str(evidence_path),
            "targetManifestSha256": (evidence.get("target") or {}).get("manifestSha256"),
            "profileSha256": (evidence.get("analysis") or {}).get("profileSha256"),
            "producer": {
                key: producer.get(key) for key in
                ("tool", "joernVersion", "revision", "image", "runtime")
            },
        }
        for logical in selected_paths:
            proof = {
                "kind": kind,
                "shape": shape,
                "variable": "interprocedural CPG path",
                "sourceKind": source_kind,
                "sinkKind": sink_kind,
                "line": (sink or source or {}).get("line"),
                **provenance,
            }
            proofs.setdefault(logical, []).append(proof)
            relationship = {
                "kind": "structural-dataflow",
                "provider": "joern-slice",
                "proofKind": kind,
                "frontend": frontend,
                "relation": relation,
                "pathId": path.get("id"),
                "source": source,
                "sink": sink,
                "crossFile": len(logical_paths) > 1,
                "evidenceArtifact": str(evidence_path),
            }
            for obs_id in triage["observationsByKindPath"].get((kind, logical), set()):
                relationships.setdefault(obs_id, []).append(relationship)
        if relation == "explicit-reaching-def":
            explicit += 1
        else:
            implicit += 1
    return proofs, relationships, explicit, implicit


class RekitJoernProvider:
    """One bounded, offline Rekit dispatcher call per selected source frontend."""

    def __init__(self, *, dispatcher: str | None = None, timeout: int = 900,
                 slice_depth: int = 12, runner: _Runner | None = None):
        self.dispatcher = dispatcher
        self.timeout = timeout
        self.slice_depth = slice_depth
        self.runner = runner or _run_command

    def analyze(self, findings: list[dict], observations: list, inv, artifact_root: str) \
            -> DeepStaticResult:
        triage = _triage(findings, observations)
        base_limitations = [
            "Joern ran only after broad native scanning selected unresolved flow questions.",
            "Each result represents one frontend/CPG and never establishes cross-language flow.",
            "Empty, unresolved, excluded, or implicit-sink slices are bounded evidence, not proof of absence.",
        ]
        summary = {
            "provider": "joern-slice",
            "enabled": True,
            "status": "not-selected",
            "profile": PROFILE_ID,
            "selectedFindings": triage["findingIds"],
            "frontends": [],
            "explicitPaths": 0,
            "implicitSinkPaths": 0,
            "unresolved": 0,
            "limitations": base_limitations,
        }
        if not triage["findingIds"]:
            return DeepStaticResult(summary=summary)
        if not 1 <= self.timeout <= 3600 or not 1 <= self.slice_depth <= 64:
            summary.update(status="unavailable", reason="Joern limits are outside supported bounds")
            return DeepStaticResult(summary=summary)

        candidate_paths = set().union(*triage["pathsByKind"].values())
        frontends = sorted({
            _FRONTEND_BY_LANGUAGE.get(getattr(entry, "language", None))
            for entry in getattr(inv, "files", [])
            if getattr(entry, "rel", None) in candidate_paths
        } - {None})
        if not frontends:
            summary.update(
                status="not-supported",
                reason="selected findings do not cite a source language with a Joern frontend",
            )
            return DeepStaticResult(summary=summary)
        if len(frontends) > _MAX_FRONTENDS:
            frontends = frontends[:_MAX_FRONTENDS]
            summary["limitations"].append(
                f"Selected frontends were truncated to the {_MAX_FRONTENDS}-frontend bound."
            )

        dispatcher = self.dispatcher or os.environ.get("UNMASK_REKIT") or shutil.which("rekit")
        if not dispatcher:
            summary.update(
                status="unavailable",
                reason="Rekit dispatcher not found; set UNMASK_REKIT or install rekit",
            )
            return DeepStaticResult(summary=summary)

        artifact_root_path = Path(artifact_root)
        artifact_root_path.mkdir(parents=True, exist_ok=True)
        all_proofs: dict[str, list[dict]] = {}
        all_relationships: dict[str, list[dict]] = {}
        artifacts: list[dict] = []
        completed = 0
        with tempfile.TemporaryDirectory(prefix="unmask-joern-") as temporary:
            temporary_root = Path(temporary)
            for frontend in frontends:
                run_summary = {"frontend": frontend, "status": "unavailable"}
                output = artifact_root_path / frontend
                try:
                    input_root = temporary_root / frontend
                    input_root.mkdir(parents=True)
                    source_map, excluded, manifest = _stage_frontend(inv, frontend, input_root)
                    command = [
                        dispatcher, "run", "joern-slice", str(input_root), str(output),
                        "--language", frontend,
                        "--mode", "behavior-flow",
                        "--profile", str(PROFILE),
                        "--slice-depth", str(self.slice_depth),
                        "--timeout", str(self.timeout),
                        "--format", "json",
                    ]
                    proc = self.runner(command, self.timeout + 30)
                    if proc.returncode != 0:
                        detail = (proc.stderr or proc.stdout or "Rekit dispatcher failed").strip()
                        raise RuntimeError(detail[-2000:])
                    evidence_path = output / "evidence.json"
                    evidence = _load_evidence(
                        evidence_path, frontend, manifest, self.timeout, self.slice_depth
                    )
                    proofs, relationships, explicit, implicit = _map_evidence(
                        evidence, frontend, source_map, triage, evidence_path
                    )
                    for logical, entries in proofs.items():
                        all_proofs.setdefault(logical, []).extend(entries)
                    for obs_id, entries in relationships.items():
                        all_relationships.setdefault(obs_id, []).extend(entries)
                    coverage = evidence.get("coverage") or {}
                    unresolved = coverage.get("unresolved") or []
                    run_summary = {
                        "frontend": frontend,
                        "status": "completed",
                        "files": len(source_map),
                        "excludedDuringStaging": excluded,
                        "producer": evidence.get("producer"),
                        "coverage": coverage,
                        "metrics": evidence.get("metrics"),
                        "explicitPaths": explicit,
                        "implicitSinkPaths": implicit,
                        "evidenceArtifact": str(evidence_path),
                    }
                    summary["explicitPaths"] += explicit
                    summary["implicitSinkPaths"] += implicit
                    summary["unresolved"] += len(unresolved)
                    completed += 1
                    for name in ("cpg.bin", "raw-slice.json", "evidence.json"):
                        path = output / name
                        if path.is_file():
                            artifacts.append({
                                "frontend": frontend,
                                "kind": "joern-" + name.removesuffix(".json").removesuffix(".bin"),
                                "path": str(path),
                                "logicalPath": f"artifacts/joern/{frontend}/{name}",
                            })
                except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
                    run_summary["reason"] = f"{type(exc).__name__}: {exc}"[-2000:]
                summary["frontends"].append(run_summary)

        if completed == len(frontends):
            summary["status"] = "completed"
        elif completed:
            summary["status"] = "partial"
        else:
            summary["status"] = "unavailable"
        return DeepStaticResult(
            summary=summary,
            proofs=all_proofs,
            relationships=all_relationships,
            artifacts=artifacts,
        )


def apply_joern_result(result: DeepStaticResult, observations: list, inv) -> None:
    """Attach structural evidence without introducing atoms or MCD judgments."""
    inv.deep_analysis = result.summary
    for logical, proofs in result.proofs.items():
        current = inv.dataflow.setdefault(logical, [])
        known = {(p.get("provider"), p.get("frontend"), p.get("pathId")) for p in current}
        for proof in proofs:
            key = (proof.get("provider"), proof.get("frontend"), proof.get("pathId"))
            if key not in known:
                current.append(proof)
                known.add(key)
    obs_by_id = {getattr(obs, "id", None): obs for obs in observations}
    for obs_id, relationships in result.relationships.items():
        obs = obs_by_id.get(obs_id)
        if obs is None:
            continue
        known = {(r.get("provider"), r.get("frontend"), r.get("pathId"))
                 for r in obs.relationships}
        for relationship in relationships:
            key = (relationship.get("provider"), relationship.get("frontend"),
                   relationship.get("pathId"))
            if key not in known:
                obs.relationships.append(relationship)
                known.add(key)


def analyze_with_joern(findings: list[dict], observations: list, inv, artifact_root: str,
                       *, dispatcher: str | None = None, timeout: int = 900,
                       slice_depth: int = 12) -> DeepStaticResult:
    try:
        return RekitJoernProvider(
            dispatcher=dispatcher, timeout=timeout, slice_depth=slice_depth
        ).analyze(findings, observations, inv, artifact_root)
    except Exception as exc:  # optional provider failure must not fail the broad scan
        return DeepStaticResult(summary={
            "provider": "joern-slice",
            "enabled": True,
            "status": "unavailable",
            "profile": PROFILE_ID,
            "selectedFindings": [],
            "frontends": [],
            "explicitPaths": 0,
            "implicitSinkPaths": 0,
            "unresolved": 0,
            "reason": f"{type(exc).__name__}: {exc}"[-2000:],
            "limitations": [
                "The optional Joern provider failed; broad native scan results remain valid.",
                "No Joern absence result is evidence that a behavior is absent.",
            ],
        })

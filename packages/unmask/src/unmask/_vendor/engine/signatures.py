"""Load taxonomy-owned signature packs for engine use.

The engine owns extraction mechanics. Signature packs own stable mappings from
already-extracted surfaces, such as callee strings, to ontology atoms.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
from typing import Optional

from .paths import taxonomy_root


class SignaturePackError(ValueError):
    """Raised when a configured signature pack is missing or malformed."""


@dataclass(frozen=True)
class SignatureRule:
    id: str
    atom: str
    surface: str
    method: str
    languages: tuple[str, ...]
    mode: str
    values: tuple[str, ...]
    confidence: float
    summary: str
    priority: int
    order: int
    case_sensitive: bool = False


@dataclass(frozen=True)
class ObservationGate:
    id: str
    atom: str
    languages: tuple[str, ...]
    needs: tuple[str, ...]
    action: str
    downweight_multiplier: float = 0.5


@dataclass(frozen=True)
class SignaturePack:
    id: str
    version: str
    path: Path
    rules: tuple[SignatureRule, ...]
    observation_gates: tuple[ObservationGate, ...]

    def classify_callee(self, callee: str, lang: str) -> Optional[tuple[str, float, str]]:
        for rule in self._rules_for(lang):
            if _matches(callee, rule):
                return (rule.atom, rule.confidence, rule.summary)
        return None

    def legacy_import_gates(self) -> list[tuple[str, str, tuple[str, ...], str]]:
        out = []
        for gate in self.observation_gates:
            for lang in gate.languages:
                out.append((lang, gate.atom, gate.needs, gate.action))
        return out

    def _rules_for(self, lang: str) -> list[SignatureRule]:
        matches = [r for r in self.rules if lang in r.languages or "*" in r.languages]
        return sorted(matches, key=lambda r: (-r.priority, r.order))


def _norm(callee: str, *, case_sensitive: bool = False) -> str:
    out = callee.replace("::", ".").replace("->", ".")
    return out if case_sensitive else out.lower()


def _matches(callee: str, rule: SignatureRule) -> bool:
    n = _norm(callee, case_sensitive=rule.case_sensitive)
    values = rule.values if rule.case_sensitive else tuple(v.lower() for v in rule.values)
    base = n.split(".")[-1]
    if rule.mode == "exact":
        return n in values
    if rule.mode == "base":
        return base in values
    if rule.mode == "suffix":
        return any(n.endswith(v) for v in values)
    if rule.mode == "exact_or_suffix":
        return any(n == v or n.endswith("." + v) for v in values)
    if rule.mode == "substring":
        return any(v in n for v in values)
    if rule.mode == "regex":
        flags = 0 if rule.case_sensitive else re.IGNORECASE
        return any(re.search(v, n, flags) for v in rule.values)
    raise SignaturePackError(f"unsupported match mode {rule.mode!r} in {rule.id}")


def resolve_source_callee_pack() -> Optional[Path]:
    explicit = os.environ.get("PRLX_SOURCE_CALLEE_PACK") or os.environ.get("PRLX_TAXONOMY_SIGNATURE_PACK")
    if explicit:
        return Path(explicit).expanduser().resolve()

    root = taxonomy_root()
    if root is None:
        return None
    for rel in ("signatures/packs/source-callees.json", "signatures/packs/source-callees.yaml"):
        path = root / rel
        if path.is_file():
            return path
    return None


def load_source_callee_pack(path: str | os.PathLike | None = None, *, required: bool = False) -> Optional[SignaturePack]:
    explicit = path is not None or bool(os.environ.get("PRLX_SOURCE_CALLEE_PACK") or os.environ.get("PRLX_TAXONOMY_SIGNATURE_PACK"))
    pack_path = Path(path).expanduser().resolve() if path is not None else resolve_source_callee_pack()
    if pack_path is None:
        if required:
            raise SignaturePackError("source callee signature pack not found")
        return None
    if not pack_path.is_file():
        msg = f"source callee signature pack not found: {pack_path}"
        if explicit or required:
            raise SignaturePackError(msg)
        return None
    return load_signature_pack(pack_path)


def load_signature_pack(path: str | os.PathLike) -> SignaturePack:
    pack_path = Path(path).expanduser().resolve()
    data = _load_mapping(pack_path)
    _validate_against_schema(data, pack_path)
    return _parse_pack(data, pack_path)


def _load_mapping(path: Path) -> dict:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        raise SignaturePackError(f"cannot read signature pack {path}: {e}") from e

    try:
        if path.suffix.lower() == ".json":
            data = json.loads(text)
        elif path.suffix.lower() in {".yaml", ".yml"}:
            try:
                import yaml
            except Exception as e:  # pragma: no cover
                raise SignaturePackError(f"PyYAML is required to load YAML signature pack {path}") from e
            data = yaml.safe_load(text)
        else:
            raise SignaturePackError(f"unsupported signature pack extension for {path}")
    except SignaturePackError:
        raise
    except Exception as e:
        raise SignaturePackError(f"malformed signature pack {path}: {e}") from e

    if not isinstance(data, dict):
        raise SignaturePackError(f"malformed signature pack {path}: top-level document must be an object")
    return data


def _validate_against_schema(data: dict, path: Path) -> None:
    schema_path = _schema_for_pack(path)
    if schema_path is None:
        _structural_validate(data, path)
        return
    try:
        import jsonschema
    except Exception:  # pragma: no cover
        _structural_validate(data, path)
        return
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator(schema).validate(data)
    except jsonschema.ValidationError as e:
        where = "/" + "/".join(map(str, e.absolute_path)) if e.absolute_path else "/"
        raise SignaturePackError(f"invalid signature pack {path}: {e.message} at {where}") from e
    except Exception as e:
        raise SignaturePackError(f"could not validate signature pack {path}: {e}") from e


def _schema_for_pack(path: Path) -> Optional[Path]:
    for parent in [path.parent, *path.parents]:
        candidate = parent / "signatures" / "schema.json"
        if candidate.is_file():
            return candidate
        candidate = parent / "schema.json"
        if candidate.is_file() and parent.name == "signatures":
            return candidate
    root = taxonomy_root()
    if root is not None and (root / "signatures" / "schema.json").is_file():
        return root / "signatures" / "schema.json"
    return None


def _structural_validate(data: dict, path: Path) -> None:
    required = ("schema_version", "id", "version", "signatures")
    missing = [k for k in required if k not in data]
    if missing:
        raise SignaturePackError(f"invalid signature pack {path}: missing {', '.join(missing)}")
    if data["schema_version"] != "parallax-signature-pack/v1":
        raise SignaturePackError(f"invalid signature pack {path}: unsupported schema_version {data['schema_version']!r}")
    if not isinstance(data.get("signatures"), list):
        raise SignaturePackError(f"invalid signature pack {path}: signatures must be a list")


def _parse_pack(data: dict, path: Path) -> SignaturePack:
    _structural_validate(data, path)
    rules = []
    for i, row in enumerate(data.get("signatures") or []):
        if row.get("surface") != "callee":
            continue
        match = row.get("match") or {}
        try:
            rules.append(SignatureRule(
                id=str(row["id"]),
                atom=str(row["atom"]),
                surface=str(row["surface"]),
                method=str(row.get("method", "static-source")),
                languages=tuple(row["languages"]),
                mode=str(match["mode"]),
                values=tuple(str(v) for v in match["values"]),
                confidence=float(row["confidence"]),
                summary=str(row["summary"]),
                priority=int(row.get("priority", 0)),
                order=i,
                case_sensitive=bool(match.get("case_sensitive", False)),
            ))
        except Exception as e:
            raise SignaturePackError(f"invalid callee signature in {path} at signatures[{i}]: {e}") from e

    gates = []
    for i, row in enumerate(data.get("observation_gates") or []):
        ctx = row.get("requires_context") or {}
        needs = ctx.get("any_text") or ctx.get("imports_any") or ctx.get("all_text") or ctx.get("imports_all")
        try:
            gates.append(ObservationGate(
                id=str(row["id"]),
                atom=str(row["atom"]),
                languages=tuple(row["languages"]),
                needs=tuple(str(v) for v in needs),
                action=str(ctx["on_missing"]),
                downweight_multiplier=float(ctx.get("downweight_multiplier", 0.5)),
            ))
        except Exception as e:
            raise SignaturePackError(f"invalid observation gate in {path} at observation_gates[{i}]: {e}") from e

    if not rules:
        raise SignaturePackError(f"invalid signature pack {path}: no callee signatures found")
    return SignaturePack(
        id=str(data["id"]),
        version=str(data["version"]),
        path=path,
        rules=tuple(rules),
        observation_gates=tuple(gates),
    )

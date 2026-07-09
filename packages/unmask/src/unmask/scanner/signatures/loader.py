"""Load `parallax-signature-pack/v1` packs into typed models.

Resolves the packs vendored into the wheel (`unmask/taxonomy/vendored/`) — no
external checkout. YAML is intentionally unsupported: the vendored packs are JSON,
keeping core dependency-free (the old engine only reached for PyYAML on `.yaml`).
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

from unmask.scanner.signatures.matcher import compile_flags
from unmask.scanner.signatures.models import ContentRule, Hit, MatchRule, SignaturePack

_SCHEMA_VERSION = "parallax-signature-pack/v1"
_MATCH_SURFACES = {"callee", "binary-import"}

# unmask/scanner/signatures/loader.py -> parents[2] == unmask package root.
_UNMASK_PKG = Path(__file__).resolve().parents[2]

_VENDORED_PACKS = {
    "callee": "source-callees.json",
    "content": "content-surfaces.json",
    "binary-import": "binary-imports.json",
}


class SignaturePackError(ValueError):
    """Raised when a signature pack is missing or malformed."""


def vendored_packs_dir() -> Path:
    return _UNMASK_PKG / "taxonomy" / "vendored" / "signatures" / "packs"


def _structural_validate(data: dict, path: Path) -> None:
    missing = [k for k in ("schema_version", "id", "version", "signatures") if k not in data]
    if missing:
        raise SignaturePackError(f"{path}: missing {', '.join(missing)}")
    if data["schema_version"] != _SCHEMA_VERSION:
        raise SignaturePackError(f"{path}: unsupported schema_version {data['schema_version']!r}")
    if not isinstance(data.get("signatures"), list):
        raise SignaturePackError(f"{path}: signatures must be a list")


def load_pack(path: str | Path) -> SignaturePack:
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as e:
        raise SignaturePackError(f"cannot read signature pack {path}: {e}") from e
    except json.JSONDecodeError as e:
        raise SignaturePackError(f"malformed signature pack {path}: {e}") from e
    if not isinstance(data, dict):
        raise SignaturePackError(f"{path}: top-level document must be an object")
    _structural_validate(data, path)

    match_rules: list[MatchRule] = []
    content_rules: list[ContentRule] = []
    for i, row in enumerate(data["signatures"]):
        surface = row.get("surface")
        try:
            if surface in _MATCH_SURFACES:
                m = row["match"]
                match_rules.append(MatchRule(
                    id=str(row["id"]), atom=str(row["atom"]), surface=str(surface),
                    method=str(row.get("method", "static-source")),
                    languages=tuple(row["languages"]),
                    mode=str(m["mode"]), values=tuple(str(v) for v in m["values"]),
                    case_sensitive=bool(m.get("case_sensitive", False)),
                    confidence=float(row["confidence"]), summary=str(row["summary"]),
                    priority=int(row.get("priority", 0)), order=i,
                ))
            elif surface == "content":
                flags = tuple(row.get("regex_flags") or ())
                content_rules.append(ContentRule(
                    id=str(row["id"]), atom=str(row["atom"]), surface="content",
                    method=str(row.get("method", "static-source")),
                    languages=tuple(row["languages"]),
                    regex=str(row["regex"]), regex_flags=flags,
                    confidence=float(row["confidence"]), summary=str(row["summary"]),
                    priority=int(row.get("priority", 0)), order=i,
                    cap_per_file=(int(row["cap_per_file"]) if row.get("cap_per_file") is not None else None),
                    mechanic=bool(row.get("mechanic", False)),
                    pattern=re.compile(str(row["regex"]), compile_flags(flags)),
                ))
            # other surfaces: ignored for now
        except (KeyError, TypeError, ValueError, re.error) as e:
            raise SignaturePackError(f"{path}: invalid signature at signatures[{i}] ({row.get('id')}): {e}") from e

    return SignaturePack(
        id=str(data["id"]), version=str(data["version"]), source=str(path),
        match_rules=tuple(match_rules), content_rules=tuple(content_rules),
    )


def _first_match(rules, candidate: str, lang: str) -> Hit | None:
    from unmask.scanner.signatures.matcher import match_symbol
    applicable = [r for r in rules if r.applies_to(lang)]
    for rule in sorted(applicable, key=lambda r: (-r.priority, r.order)):
        if match_symbol(candidate, rule):
            return Hit(rule.atom, rule.confidence, rule.summary, rule.id)
    return None


class Signatures:
    """Facade over the vendored packs: classify callees, imports, and content."""

    def __init__(self, packs: dict[str, SignaturePack]):
        self.packs = packs

    @classmethod
    def load_vendored(cls, packs_dir: Path | None = None) -> "Signatures":
        """Load the vendored packs. Cached (packs are read-only and re-parsing +
        recompiling ~100 regexes on every scan node — observe, transform, fetch — is
        pure waste); the returned facade is safe to share."""
        return _load_vendored_cached(str(packs_dir) if packs_dir is not None else None)

    @property
    def callee_rules(self) -> tuple[MatchRule, ...]:
        return self.packs["callee"].match_rules

    def known_atoms(self) -> frozenset[str]:
        """Every atom the vendored packs can assign — the canonical vocabulary an
        RE skill's emitted atoms are validated against before ingestion."""
        atoms: set[str] = set()
        for pack in self.packs.values():
            atoms.update(r.atom for r in pack.match_rules)
            atoms.update(r.atom for r in pack.content_rules)
        return frozenset(atoms)

    def known_families(self) -> frozenset[str]:
        """Atom family prefixes (the part before the dot). Ingestion validates by
        family, not exact atom, so a skill may emit a newer subtype in a known
        family (e.g. a future ``XFRM.*``) without core gatekeeping it — but a
        garbage family is rejected. Some families are emitted by passes/RE skills, not
        the core packs, and are whitelisted here the same way: ``AITM`` (prompt-injection,
        from the manifest/content passes) and ``OBF``/``EVADE``/``STEGO`` (obfuscation
        tactics, environment-keyed evasion, steganography — from the js/py covert-scan
        skills)."""
        fams = {a.split(".", 1)[0] for a in self.known_atoms()}
        fams.update({"AITM", "OBF", "EVADE", "STEGO"})
        return frozenset(fams)

    def classify_callee(self, callee: str, lang: str) -> Hit | None:
        return _first_match(self.callee_rules, callee, lang)

    def classify_import(self, symbol: str, lang: str = "*") -> Hit | None:
        pack = self.packs.get("binary-import")
        return _first_match(pack.match_rules, symbol, lang) if pack else None

    def classify_content(self, text: str, lang: str = "*") -> list[Hit]:
        from unmask.scanner.signatures.matcher import content_matches
        pack = self.packs.get("content")
        if not pack:
            return []
        hits: list[Hit] = []
        for rule in pack.content_rules:
            if not rule.applies_to(lang):
                continue
            for matched, start in content_matches(text, rule):
                hits.append(Hit(rule.atom, rule.confidence, rule.summary, rule.id, text=matched, start=start))
        return hits


@lru_cache(maxsize=8)
def _load_vendored_cached(packs_dir_str: str | None) -> "Signatures":
    packs_dir = Path(packs_dir_str) if packs_dir_str is not None else vendored_packs_dir()
    loaded: dict[str, SignaturePack] = {}
    for name, fname in _VENDORED_PACKS.items():
        fp = packs_dir / fname
        if fp.is_file():
            loaded[name] = load_pack(fp)
    if "callee" not in loaded:
        raise SignaturePackError(f"no callee pack under {packs_dir}")
    return Signatures(loaded)

"""Data-driven inventory: walk a target and classify each file.

Classification is driven entirely by `reference/file-classification.json`
(skip_dirs / manifest_names / lang_by_ext / binary_exts / lang_by_name /
ecosystem_by_name) — no hardcoded tables. This is the reveal-free first pass;
container expansion (asar/zip) is a later slice.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from unmask.scanner.refdata import load_reference

# Kinds that carry text worth scanning for atoms.
_SCANNABLE = {"source", "manifest", "text"}
_TEXT_EXTS = {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".txt", ".md", ".xml"}


@dataclass(frozen=True)
class FileEntry:
    path: str          # absolute
    rel: str           # relative to the target root
    kind: str          # source | manifest | binary | text | other
    language: str | None = None
    ecosystem: str | None = None
    size: int = 0


@dataclass
class Inventory:
    root: str
    files: list[FileEntry] = field(default_factory=list)
    # Lowercased manifest/README description — a weak "stated purpose" signal used
    # by BP-TROJAN (behavior that doesn't match what the package claims to be).
    purpose: str = ""
    # Intra-file taint results: {relpath: [proven-path dicts]} (see observe.dataflow).
    dataflow: dict = field(default_factory=dict)
    # Cross-file reachability: {"reachableSinks": [...], ...} (see observe.callgraph).
    reachability: dict = field(default_factory=dict)
    # Optional post-triage structural evidence and its coverage/provenance summary.
    deep_analysis: dict = field(default_factory=dict)

    def scannable(self) -> list[FileEntry]:
        return [f for f in self.files if f.kind in _SCANNABLE]

    def source_files(self) -> list[FileEntry]:
        return [f for f in self.files if f.kind in {"source", "manifest"}]

    def binaries(self) -> list[FileEntry]:
        return [f for f in self.files if f.kind == "binary"]

    def manifests(self) -> list[FileEntry]:
        return [f for f in self.files if f.kind == "manifest"]


class _Classifier:
    def __init__(self):
        fc = load_reference("file-classification") or {}
        self.skip_dirs = set(fc.get("skip_dirs") or [])
        self.manifest_names = set(fc.get("manifest_names") or [])
        self.lang_by_ext = dict(fc.get("lang_by_ext") or {})
        self.binary_exts = dict(fc.get("binary_exts") or {})
        self.lang_by_name = dict(fc.get("lang_by_name") or {})
        self.ecosystem_by_name = dict(fc.get("ecosystem_by_name") or {})

    def classify(self, path: Path, rel: str, size: int) -> FileEntry:
        name, ext = path.name, path.suffix.lower()
        language = self.lang_by_name.get(name) or self.lang_by_ext.get(ext)
        ecosystem = self.ecosystem_by_name.get(name)
        if name in self.manifest_names:
            kind = "manifest"
        elif ext in self.binary_exts:
            kind = "binary"
        elif language is not None:
            kind = "source"
        elif ext in _TEXT_EXTS:
            kind = "text"
        else:
            kind = "other"
        return FileEntry(str(path), rel, kind, language, ecosystem, size)


def build_inventory(target: str) -> Inventory:
    root = Path(target).resolve()
    clf = _Classifier()
    inv = Inventory(root=str(root))

    if root.is_file():
        inv.files.append(clf.classify(root, root.name, _safe_size(root)))
        return inv

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in clf.skip_dirs]
        for fname in filenames:
            fp = Path(dirpath) / fname
            if fp.is_symlink():
                continue
            rel = str(fp.relative_to(root))
            inv.files.append(clf.classify(fp, rel, _safe_size(fp)))
    inv.files.sort(key=lambda f: f.rel)
    inv.purpose = _derive_purpose(root)
    return inv


def _derive_purpose(root: Path) -> str:
    """Lowercased name/description from a manifest, else the README's first heading."""
    import json as _json

    bits: list[str] = []
    for nm in ("package.json", "mcp.json", "server.json"):
        p = root / nm
        if p.is_file():
            try:
                d = _json.loads(p.read_text(encoding="utf-8", errors="replace"))
                bits += [d[k] for k in ("description", "name") if isinstance(d.get(k), str)]
            except (ValueError, OSError):
                pass
    pp = root / "pyproject.toml"
    if pp.is_file():
        try:
            import tomllib
            proj = (tomllib.loads(pp.read_text(encoding="utf-8")).get("project") or {})
            bits += [proj[k] for k in ("description", "name") if isinstance(proj.get(k), str)]
        except Exception:
            pass
    if not bits:
        for rn in ("README.md", "readme.md", "README"):
            rp = root / rn
            if rp.is_file():
                for line in rp.read_text(encoding="utf-8", errors="replace").splitlines():
                    s = line.strip().lstrip("#").strip()
                    if s:
                        bits.append(s)
                        break
                break
    return " ".join(bits).lower()


def _safe_size(p: Path) -> int:
    try:
        return p.stat().st_size
    except OSError:
        return 0

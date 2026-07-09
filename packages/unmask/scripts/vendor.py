#!/usr/bin/env python3
"""Vendor the deterministic scanner (engine + mcd_lens) and taxonomy DATA into
the `unmask` wheel so it is fully self-contained — no runtime dependency on an
external ``parallax-goalpacks`` or ``parallax-taxonomy`` checkout.

Sources are treated as READ-ONLY. What lands in the wheel:

  src/unmask/_vendor/engine       <- parallax-goalpacks/engine  (pure stdlib)
  src/unmask/_vendor/mcd_lens     <- parallax-goalpacks/mcd_lens (pure stdlib)
  src/unmask/taxonomy/vendored/   <- parallax-taxonomy (allowlisted roots only)

The taxonomy copy is ALLOWLISTED: only ``signatures/`` (schema.json + packs/* +
examples/), ``reference/*.json``, and ``ontology/atom-registry.json`` (the
skill-emitted OBF/EVADE/STEGO atom vocabulary the core validates against).
Everything else in the taxonomy repo (``.git``, ``.venv``, doc roots, the rest of
``ontology/`` (markdown atoms), the nested ``parallax/`` subrepo, ``scripts/``,
``tests/``) is intentionally excluded.

A ``taxonomy-manifest.json`` records the source git commit and a sha256 of every
vendored taxonomy file, so CI can detect drift with ``--check``.

Usage::

    python scripts/vendor.py                 # (re)vendor from default sibling sources
    python scripts/vendor.py --check         # fail if vendored tree is stale/missing
    python scripts/vendor.py \
        --goalpacks /path/to/parallax-goalpacks \
        --taxonomy  /path/to/parallax-taxonomy
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

# scripts/ -> packages/unmask/ -> src/unmask
PKG_ROOT = Path(__file__).resolve().parents[1]
UNMASK_SRC = PKG_ROOT / "src" / "unmask"
VENDOR_DIR = UNMASK_SRC / "_vendor"
TAXONOMY_DIR = UNMASK_SRC / "taxonomy" / "vendored"
MANIFEST_PATH = TAXONOMY_DIR / "taxonomy-manifest.json"

# Repo layout: mcd/packages/unmask/scripts -> ... -> runner-lab/
RUNNER_LAB = PKG_ROOT.parents[2]
DEFAULT_GOALPACKS = RUNNER_LAB / "parallax-goalpacks"
DEFAULT_TAXONOMY = RUNNER_LAB / "parallax-taxonomy"

COPY_EXCLUDES = {"__pycache__", ".DS_Store"}
# Taxonomy allowlist: which roots are vendored, and (for reference) which
# extensions. signatures/ is copied wholesale (minus junk); reference/ is json-only.
SIGNATURES_ROOT = "signatures"
REFERENCE_ROOT = "reference"
ONTOLOGY_ROOT = "ontology"
# Only this one JSON file is taken from ontology/ (the rest is markdown docs).
ATOM_REGISTRY_REL = Path("ontology") / "atom-registry.json"
TAXONOMY_MARKER = Path("signatures") / "schema.json"

SCHEMA_VERSION = "0.1.0"
TAXONOMY_ID = "parallax-taxonomy"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _ignore(_dir, names):
    return [n for n in names if n in COPY_EXCLUDES or n.endswith(".pyc")]


def _copy_tree(src: Path, dst: Path) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst, ignore=_ignore)


def _copy_reference_json(src: Path, dst: Path) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    dst.mkdir(parents=True, exist_ok=True)
    for p in sorted(src.glob("*.json")):
        shutil.copy2(p, dst / p.name)


def _copy_atom_registry(taxonomy: Path) -> None:
    src = taxonomy / ATOM_REGISTRY_REL
    if not src.is_file():
        sys.exit(f"error: atom registry {ATOM_REGISTRY_REL} not found under {taxonomy}")
    dst = TAXONOMY_DIR / ATOM_REGISTRY_REL
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def _git_commit(repo: Path) -> str:
    try:
        out = subprocess.check_output(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            stderr=subprocess.DEVNULL,
        )
        return out.decode().strip()
    except Exception:
        return "unknown"


def _iter_taxonomy_files() -> list[Path]:
    return sorted(p for p in TAXONOMY_DIR.rglob("*") if p.is_file() and p.name != MANIFEST_PATH.name)


def _build_manifest(source_commit: str) -> dict:
    files = []
    for p in _iter_taxonomy_files():
        files.append({"path": p.relative_to(TAXONOMY_DIR).as_posix(), "sha256": _sha256(p)})
    return {
        "schemaVersion": SCHEMA_VERSION,
        "taxonomyId": TAXONOMY_ID,
        "sourceGitCommit": source_commit,
        "includedRoots": [SIGNATURES_ROOT, REFERENCE_ROOT, ONTOLOGY_ROOT],
        "files": files,
    }


def do_vendor(goalpacks: Path, taxonomy: Path) -> None:
    if not (goalpacks / "engine" / "__init__.py").is_file():
        sys.exit(f"error: engine not found under {goalpacks}")
    if not (goalpacks / "mcd_lens" / "__init__.py").is_file():
        sys.exit(f"error: mcd_lens not found under {goalpacks}")
    if not (taxonomy / TAXONOMY_MARKER).is_file():
        sys.exit(f"error: taxonomy marker {TAXONOMY_MARKER} not found under {taxonomy}")

    VENDOR_DIR.mkdir(parents=True, exist_ok=True)
    _copy_tree(goalpacks / "engine", VENDOR_DIR / "engine")
    _copy_tree(goalpacks / "mcd_lens", VENDOR_DIR / "mcd_lens")

    # Rebuild the vendored taxonomy from scratch so any non-allowlisted roots
    # left over from an earlier copy are pruned. Only signatures/ + reference/
    # (and the generated manifest) are allowed to exist here.
    if TAXONOMY_DIR.exists():
        shutil.rmtree(TAXONOMY_DIR)
    TAXONOMY_DIR.mkdir(parents=True, exist_ok=True)
    _copy_tree(taxonomy / SIGNATURES_ROOT, TAXONOMY_DIR / SIGNATURES_ROOT)
    _copy_reference_json(taxonomy / REFERENCE_ROOT, TAXONOMY_DIR / REFERENCE_ROOT)
    _copy_atom_registry(taxonomy)

    if not (TAXONOMY_DIR / TAXONOMY_MARKER).is_file():
        sys.exit(f"error: vendored taxonomy is missing marker {TAXONOMY_MARKER}")

    manifest = _build_manifest(_git_commit(taxonomy))
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"vendored engine + mcd_lens -> {VENDOR_DIR}")
    print(f"vendored taxonomy ({len(manifest['files'])} files) -> {TAXONOMY_DIR}")
    print(f"manifest @ commit {manifest['sourceGitCommit']}")


def do_check() -> int:
    if not MANIFEST_PATH.is_file():
        print("STALE: taxonomy-manifest.json missing")
        return 1
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    recorded = {e["path"]: e["sha256"] for e in manifest.get("files", [])}
    on_disk = {p.relative_to(TAXONOMY_DIR).as_posix(): _sha256(p) for p in _iter_taxonomy_files()}
    problems = []
    for path, digest in recorded.items():
        if path not in on_disk:
            problems.append(f"missing: {path}")
        elif on_disk[path] != digest:
            problems.append(f"changed: {path}")
    for path in on_disk:
        if path not in recorded:
            problems.append(f"untracked: {path}")
    if problems:
        print("STALE vendored taxonomy:")
        for p in problems:
            print(f"  {p}")
        print("Re-run: python scripts/vendor.py")
        return 1
    print(f"OK: {len(recorded)} vendored taxonomy files match manifest")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--goalpacks", type=Path, default=DEFAULT_GOALPACKS)
    ap.add_argument("--taxonomy", type=Path, default=DEFAULT_TAXONOMY)
    ap.add_argument("--check", action="store_true", help="verify vendored taxonomy matches its manifest")
    args = ap.parse_args()
    if args.check:
        return do_check()
    do_vendor(args.goalpacks.expanduser().resolve(), args.taxonomy.expanduser().resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

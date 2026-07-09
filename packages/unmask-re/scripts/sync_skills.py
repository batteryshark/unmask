#!/usr/bin/env python3
"""sync_skills — vendor the rekit skills unmask-re needs, standalone.

Copies an allowlisted set of skills from a rekit checkout (``--rekit-root``,
defaults to the sibling ``../../rekit``) into ``packages/unmask-re/skills/`` so
the unmask-re wheel is fully self-contained: no rekit checkout is needed at
install or run time.

Each copied skill is a self-contained payload (vendored node_modules / site deps
committed, or a BYO-tool runner that shells out to a CLI on PATH). The copy is
refreshable: re-run this script to pull skill updates from rekit. A
``skills-manifest.json`` records the source path, the allowlist, and a per-skill
sha256 over the runner files so drift is detectable.

Usage:
    python scripts/sync_skills.py                 # copy from ../../rekit
    python scripts/sync_skills.py --check         # exit 1 if vendored is stale
    python scripts/sync_skills.py --rekit-root /path/to/rekit

The allowlist is the single source of truth for which skills ship. Add a skill
id here to start vendoring it; the provider picks it up automatically from the
manifest at import time.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path

# rekit skill manifests live in ONE central registry.json (keyed by id); we read the
# entry for each vendored skill from there — plain JSON, no YAML parser needed.

# Skills unmask-re ships. Each must exist under <rekit-root>/skills/<id>/ with a
# SKILL.md. Kept conservative: only the transform/atom-emission skills core's
# transform seam can actually drive. Dynamic-exec / frida / qiling / net-capture
# skills are deliberately excluded — they belong to the (deferred) sandbox
# milestone, not the v0.1 static+transform scope.
ALLOWED_SKILLS = (
    "unpack",                # pure stdlib: zip/tar/gz/bz2/xz/asar — the container reveal
    "bin-triage",            # pure stdlib emit-atoms: format/entropy/strings/signatures
    "js-deobfuscate",        # vendored webcrack: deobfuscate JS / unpack bundles
    "jvm-decompile",         # BYO jadx: apk/dex/jar/class -> java
    "dotnet-decompile",      # BYO ilspycmd: .NET assembly -> C#
    "pyc-decompile",         # vendored decompyle3: .pyc -> py
    "js-covert-scan",        # pure stdlib emit-atoms: stego/obf/evasion in JS
    "js-string-decode",      # pure stdlib: static constant-key XOR/charCode string decode
    "py-covert-scan",        # pure stdlib emit-atoms: stego/obf/evasion in Python
    "secrets-scan",          # pure stdlib emit-atoms: leaked credentials
)

# Files/dirs never copied from a skill (build scratch, caches, OS noise).
EXCLUDE_NAMES = {".DS_Store", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".git"}


def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _has_excluded_segment(p: Path) -> bool:
    return any(part in EXCLUDE_NAMES for part in p.parts)


def _skill_hash(skill_dir: Path) -> str:
    """sha256 over the sorted, non-excluded file contents of a skill — drift detect."""
    h = hashlib.sha256()
    for f in sorted(skill_dir.rglob("*")):
        if f.is_dir() or _has_excluded_segment(f.relative_to(skill_dir)):
            continue
        rel = f.relative_to(skill_dir).as_posix()
        h.update(rel.encode())
        h.update(b"\0")
        h.update(_sha256_file(f).encode())
        h.update(b"\0")
    return h.hexdigest()


def _copy_skill(src: Path, dst: Path) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    dst.mkdir(parents=True, exist_ok=True)

    def ignore(_, names):
        return [n for n in names if n in EXCLUDE_NAMES]
    shutil.copytree(src, dst, dirs_exist_ok=True, ignore=ignore)


def sync(rekit_root: Path, dest: Path) -> dict:
    skills_src = rekit_root / "skills"
    if not skills_src.is_dir():
        raise SystemExit(f"rekit skills dir not found: {skills_src}")
    registry_path = rekit_root / "registry.json"
    if not registry_path.is_file():
        raise SystemExit(f"rekit registry not found: {registry_path}")
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    dest.mkdir(parents=True, exist_ok=True)
    records = []
    for sid in ALLOWED_SKILLS:
        src = skills_src / sid
        if not src.is_dir() or not (src / "SKILL.md").is_file() or sid not in registry:
            print(f"  ! {sid}: missing dir/SKILL.md or no registry entry in {rekit_root}, skipping", file=sys.stderr)
            continue
        dst = dest / sid
        _copy_skill(src, dst)
        manifest = registry[sid]
        records.append({
            "id": sid,
            "name": manifest.get("name", sid),
            "version": manifest.get("version", "0"),
            "capabilities": list(manifest.get("capabilities", [])),
            "prerequisites": manifest.get("prerequisites", []),
            "entry": manifest.get("entry", {}),
            "sha256": _skill_hash(dst),
        })
        print(f"  + {sid}: {len(list(dst.rglob('*')))} files")
    return {
        "schemaVersion": "0.1.0",
        # Provenance label only (never read at run time) — keep it a name, not an
        # absolute machine path, so the committed manifest doesn't leak local paths.
        "sourceRoot": rekit_root.name,
        "skills": records,
    }


def check(rekit_root: Path, dest: Path) -> int:
    """Exit 1 if any vendored skill has drifted from its rekit source."""
    manifest_path = dest / "skills-manifest.json"
    if not manifest_path.is_file():
        print("STALE: no skills-manifest.json (run sync_skills.py)", file=sys.stderr)
        return 1
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    skills_src = rekit_root / "skills"
    stale = 0
    for rec in manifest.get("skills", []):
        sid = rec["id"]
        src = skills_src / sid
        if not src.is_dir():
            continue
        current = _skill_hash(src)
        if current != rec.get("sha256"):
            print(f"STALE: {sid} differs from rekit source", file=sys.stderr)
            stale += 1
    if stale:
        print(f"{stale} skill(s) stale — re-run sync_skills.py", file=sys.stderr)
    else:
        print("OK: vendored skills match rekit source")
    return 1 if stale else 0


def main(argv: list[str] | None = None) -> int:
    here = Path(__file__).resolve().parent
    default_rekit = here.parent.parent.parent.parent / "rekit"  # scripts -> unmask-re -> packages -> repo -> sibling rekit
    default_dest = here.parent / "skills"
    p = argparse.ArgumentParser(description="vendor rekit skills into unmask-re")
    p.add_argument("--rekit-root", default=str(default_rekit), help="path to a rekit checkout")
    p.add_argument("--dest", default=str(default_dest), help="destination skills dir")
    p.add_argument("--check", action="store_true", help="exit 1 if vendored skills are stale")
    a = p.parse_args(argv)
    rekit_root = Path(a.rekit_root)
    dest = Path(a.dest)
    if a.check:
        return check(rekit_root, dest)
    manifest = sync(rekit_root, dest)
    manifest_path = dest / "skills-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"\nWrote {manifest_path} ({len(manifest['skills'])} skills)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

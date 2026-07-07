"""Container reveal: unpack packed targets so the scanner sees the real code.

Malicious code hides behind packing — an Electron app ships its JS inside
`app.asar`; a dropped payload arrives as a `.zip` that contains an asar that
contains the JS. Scanning the raw bytes finds nothing. This pass unpacks every
container it can, recursively, to a fixpoint, into a run-scoped `revealed/` dir,
so the observe passes then read the *revealed* source.

Safe and bounded by design: extraction only (never executes anything), path
traversal (zip-slip) is blocked, extraction is capped (unpacks / passes / member
size), and a container is keyed by content hash so the same bytes are never
unpacked twice. Best-effort: a container that fails to extract is skipped, and the
run continues on whatever was revealed.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import struct
import tarfile
import zipfile
from pathlib import Path

# Archive/container kinds we can open with the standard library + a small asar parser.
_ARCHIVE_EXTS = {".zip", ".whl", ".egg", ".jar", ".aar", ".apk", ".asar",
                 ".tar", ".gz", ".tgz", ".bz2", ".xz"}
_SKIP_DIRS = {".git", "node_modules", ".venv", "__pycache__", "dist", "build"}

_MAX_UNPACKS = 24        # total containers unpacked per run
_MAX_PASSES = 6          # recursion depth (zip -> asar -> ...)
_MAX_MEMBER_BYTES = 64_000_000
_ASAR_MAGIC = 4          # first uint32 of a Chromium Pickle asar header


def is_container(path: Path) -> bool:
    return path.suffix.lower() in _ARCHIVE_EXTS


def _file_hash(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_join(dest_root: Path, member: str) -> Path | None:
    """Resolve a member path inside dest_root, or None if it escapes (zip-slip)."""
    dest_root = dest_root.resolve()
    p = (dest_root / member).resolve()
    try:
        p.relative_to(dest_root)
    except ValueError:
        return None
    return p


# --- extractors ------------------------------------------------------------

def _extract_zip(path: Path, dest: Path) -> bool:
    try:
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                if info.is_dir() or info.file_size > _MAX_MEMBER_BYTES:
                    continue
                out = _safe_join(dest, info.filename)
                if out is None:
                    continue
                out.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, open(out, "wb") as dst:
                    dst.write(src.read())
        return True
    except (zipfile.BadZipFile, OSError, ValueError):
        return False


def _extract_tar(path: Path, dest: Path) -> bool:
    try:
        with tarfile.open(path) as tf:
            # Python 3.12+ data filter blocks absolute paths, traversal, devices, links.
            tf.extractall(dest, filter="data")
        return True
    except (tarfile.TarError, OSError, ValueError):
        return False


def _extract_gzip(path: Path, dest: Path) -> bool:
    try:
        out = dest / (path.stem or "decompressed")
        with gzip.open(path, "rb") as src, open(out, "wb") as dst:
            total = 0
            for chunk in iter(lambda: src.read(1 << 16), b""):
                total += len(chunk)
                if total > _MAX_MEMBER_BYTES:
                    break
                dst.write(chunk)
        return True
    except (OSError, EOFError):
        return False


def _asar_write_entries(node: dict, prefix: str, data: bytes, base: int, dest: Path) -> None:
    for name, entry in node.items():
        if not isinstance(entry, dict):
            continue
        if "files" in entry:  # directory
            _asar_write_entries(entry["files"], f"{prefix}{name}/", data, base, dest)
        elif "offset" in entry and "size" in entry:
            off, size = int(entry["offset"]), int(entry["size"])
            if size > _MAX_MEMBER_BYTES or off < 0 or base + off + size > len(data):
                continue
            out = _safe_join(dest, prefix + name)
            if out is None:
                continue
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(data[base + off:base + off + size])


def _extract_asar(path: Path, dest: Path) -> bool:
    """Parse an Electron asar (Chromium Pickle framing) and write its files."""
    try:
        data = path.read_bytes()
        if len(data) < 16:
            return False
        magic, header_size, _payload_size, json_len = struct.unpack("<IIII", data[:16])
        if magic != _ASAR_MAGIC:
            return False
        header = json.loads(data[16:16 + json_len].decode("utf-8", "replace"))
        data_base = 8 + header_size  # framing: header_size counts payload_size's own uint32
        _asar_write_entries(header.get("files", {}), "", data, data_base, dest)
        return True
    except (struct.error, json.JSONDecodeError, OSError, ValueError, KeyError):
        return False


def _extract(path: Path, dest: Path) -> bool:
    ext = path.suffix.lower()
    if ext == ".asar":
        return _extract_asar(path, dest)
    if ext in {".zip", ".whl", ".egg", ".jar", ".aar", ".apk"}:
        return _extract_zip(path, dest)
    if ext in {".tar", ".tgz", ".bz2", ".xz"} or (ext == ".gz" and path.name.endswith((".tar.gz",))):
        return _extract_tar(path, dest)
    if ext == ".gz":
        return _extract_gzip(path, dest)
    return False


# --- reveal fixpoint -------------------------------------------------------

def _find_containers(root: Path) -> list[Path]:
    if root.is_file():
        return [root] if is_container(root) else []
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in filenames:
            p = Path(dirpath) / name
            if is_container(p):
                out.append(p)
    return out


def reveal(target: str | Path, dest_dir: str | Path, *, max_unpacks: int = _MAX_UNPACKS) -> list[tuple[Path, str]]:
    """Recursively unpack containers under `target` into `dest_dir`.

    Returns [(extracted_root_dir, origin_label)] — the revealed trees and where each
    came from (a `container!member` style label). A pass that reveals nothing stops
    the loop; content-hash dedup prevents re-unpacking the same bytes.
    """
    target = Path(target)
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    revealed: list[tuple[Path, str]] = []
    seen: set[str] = set()
    roots = [target]
    unpacks = 0

    for _ in range(_MAX_PASSES):
        next_roots: list[Path] = []
        for root in roots:
            for container in _find_containers(root):
                if unpacks >= max_unpacks:
                    return revealed
                digest = _file_hash(container)
                if digest in seen:
                    continue
                seen.add(digest)
                out = dest_dir / digest[:12]
                out.mkdir(parents=True, exist_ok=True)
                if _extract(container, out):
                    unpacks += 1
                    try:
                        origin = str(container.relative_to(target)) if target.is_dir() else container.name
                    except ValueError:
                        origin = container.name
                    revealed.append((out, origin))
                    next_roots.append(out)
        if not next_roots:
            break
        roots = next_roots
    return revealed

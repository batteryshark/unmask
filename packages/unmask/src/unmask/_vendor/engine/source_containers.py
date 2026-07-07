"""Bounded source-container expansion before source rules run.

Some desktop/app artifacts are containers whose interesting code is inside the
artifact rather than beside it. This module is the transform seam: extract safe,
text-like source members into a temporary tree, add them to the inventory with
stable synthetic paths (`app.asar!out/main/index.js`), then let the normal source
pipeline read them. It never executes target bytes.

Current producers are intentionally narrow: ASAR is implemented first because it
has a simple file table and common Electron packaging shape. Zip-family,
Tauri/PyInstaller, and decompiler output can reuse `_add_source_member` when
their binary/string-triage contracts are made equally precise.
"""

from __future__ import annotations

import os
import posixpath
import tempfile

from . import binary
from .inventory import FileEntry, LANG_BY_EXT, LANG_BY_NAME, _ECOSYSTEM_BY_NAME

def _ext(name: str) -> str:
    return posixpath.splitext(name)[1].lower()


def _safe_member_name(name: str) -> str | None:
    raw = str(name).replace("\\", "/")
    if "\x00" in raw:
        return None
    parts = [p for p in raw.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        return None
    norm = posixpath.normpath(raw)
    if norm in ("", ".") or norm.startswith("/") or norm == ".." or norm.startswith("../"):
        return None
    if "/../" in norm:
        return None
    return norm


def _member_lang(member: str) -> str | None:
    name = posixpath.basename(member)
    return LANG_BY_NAME.get(name) or LANG_BY_EXT.get(_ext(name))


def _looks_text(data: bytes) -> bool:
    if not data:
        return False
    sample = data[:4096]
    if b"\x00" in sample:
        return False
    noisy = sum(1 for b in sample if b < 32 and b not in b"\t\n\r\f\b")
    return noisy <= max(8, len(sample) // 20)


def _write_member(tmp_root: str, synthetic_relpath: str, data: bytes) -> str:
    local_parts = synthetic_relpath.replace("\\", "/").split("/")
    out_path = os.path.join(tmp_root, *local_parts)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "wb") as fh:
        fh.write(data)
    return out_path


def _add_source_member(inv, container, tmp_root: str, member: str, data: bytes) -> bool:
    lang = _member_lang(member)
    if not lang or not _looks_text(data):
        return False
    name = posixpath.basename(member)
    synthetic = f"{container.relpath}!{member}"
    abspath = _write_member(tmp_root, synthetic, data)
    inv.files.append(FileEntry(abspath=abspath, relpath=synthetic, lang=lang, name=name))
    eco = _ECOSYSTEM_BY_NAME.get(name)
    if eco:
        inv.ecosystems.add(eco)
    return True


def _asar_sources(inv, container, tmp_root: str) -> dict:
    result = {
        "container": container.relpath,
        "kind": "asar",
        "sourceMembers": 0,
        "skippedMembers": 0,
        "truncated": False,
        "notes": [],
    }
    try:
        with open(container.abspath, "rb") as fh:
            header, payload_start, error = binary._read_asar_header(fh)
            if error or not header:
                result["notes"].append(error or "ASAR header unreadable")
                return result
            archive_size = binary._file_size(fh)
            candidates = []
            for raw_name, meta in binary._iter_asar_files(header):
                member = _safe_member_name(raw_name)
                if not member or meta.get("unpacked") or not _member_lang(member):
                    result["skippedMembers"] += 1
                    continue
                if binary._asar_member_span(meta, payload_start, archive_size) is None:
                    result["skippedMembers"] += 1
                    continue
                candidates.append((member, meta))
            candidates.sort(key=binary._asar_member_priority)

            total = 0
            if len(candidates) > binary._ARCHIVE_MAX_MEMBERS:
                result["truncated"] = True
            for member, meta in candidates[:binary._ARCHIVE_MAX_MEMBERS]:
                if total >= binary._ARCHIVE_MAX_TOTAL:
                    result["truncated"] = True
                    break
                try:
                    span = binary._asar_member_span(meta, payload_start, archive_size)
                    if span is None:
                        result["skippedMembers"] += 1
                        continue
                    offset, declared_size = span
                    size = min(declared_size, binary._ARCHIVE_MAX_MEMBER_BYTES)
                    fh.seek(payload_start + offset)
                    data = fh.read(size)
                except Exception:
                    result["skippedMembers"] += 1
                    continue
                total += len(data)
                if binary._looks_like_textmate_grammar_member(member, data):
                    result["skippedMembers"] += 1
                    continue
                if _add_source_member(inv, container, tmp_root, member, data):
                    result["sourceMembers"] += 1
                else:
                    result["skippedMembers"] += 1
    except Exception:
        result["notes"].append("ASAR archive unreadable")
    return result


def expand(inv) -> None:
    """Add extracted source members to `inv.files`.

    The temporary tree is kept alive on the inventory until `cleanup()` runs.
    """
    containers = []
    for f in list(getattr(inv, "files", [])):
        if getattr(f, "lang", None) != "binary":
            continue
        ext = _ext(f.name)
        if ext == ".asar":
            containers.append((f, ext))
    if not containers:
        return

    tmp = tempfile.TemporaryDirectory(prefix="prlx-source-containers-")
    inv._artifact_tempdirs.append(tmp)
    for container, ext in containers:
        result = _asar_sources(inv, container, tmp.name)
        if result["sourceMembers"] or result["notes"]:
            inv.artifact_transforms.append(result)


def cleanup(inv) -> None:
    for tmp in getattr(inv, "_artifact_tempdirs", []):
        try:
            tmp.cleanup()
        except Exception:
            pass
    inv._artifact_tempdirs.clear()

"""Binary artifact triage at lightweight-to-structural static depth.

Self-contained and safe: detects compiled / binary artifacts by magic bytes and
extension, hashes them (SHA-256), measures Shannon entropy, looks for known packer
signatures, recurses into ZIP-family archives (JAR/APK/wheel/ZIP), and extracts
printable strings to run the shared content rules over (a C2 URL or an embedded key
reads the same in an ELF as in a .py file). It NEVER executes anything and NEVER
decompiles. Deep behavior (managed or native decompilation) is a declared blind
spot, recorded per artifact so the report says plainly what it could not see.

Analysis levels (see docs/BINARY_ANALYSIS.md): this module covers level 1-2 (inventory,
lightweight static triage, structure: entropy/packer/archive recursion). Import-
table capability inference and decompilation with tools such as JADX, CFR,
ILSpy, or Ghidra are higher levels; decompilation would feed its output back
through the same rules. Everything here is read-only and bounded against zip
bombs.
"""

from __future__ import annotations

import collections
import hashlib
import io
import json
import math
import os
import posixpath
import re
import shutil
import struct
import zipfile

from .bincaps import analyze as analyze_caps
from .inventory import BINARY_EXTS, LANG_BY_EXT, MANIFEST_NAMES
from .model import Observation
from .rules import scan_strings

# Magic-byte signatures, checked before extension (more specific).
_MAGIC = [
    (b"\x7fELF", "ELF binary (native executable/library)"),
    (b"MZ", "PE binary (Windows executable/DLL)"),
    (b"\xfe\xed\xfa\xce", "Mach-O binary"),
    (b"\xfe\xed\xfa\xcf", "Mach-O binary (64-bit)"),
    (b"\xcf\xfa\xed\xfe", "Mach-O binary (64-bit)"),
    (b"\xce\xfa\xed\xfe", "Mach-O binary"),
    (b"\xca\xfe\xba\xbe", "Java class or Mach-O fat binary"),
    (b"dex\n", "Android DEX"),
    (b"\x00asm", "WebAssembly module"),
    (b"PK\x03\x04", "ZIP / JAR / archive"),
    (b"!<arch>", "static archive (ar)"),
    (b"\xed\xab\xee\xdb", "RPM package"),
]

_MAX_BYTES = 8_000_000          # cap bytes read per sample window
_MAX_SAMPLE_WINDOWS = 16        # bounded coverage across large standalone bundles
_MAX_TAIL_WINDOWS = 8           # contiguous suffix coverage for appended runtimes
_MAX_STRINGS_TEXT = 1_000_000   # cap extracted-strings text fed to the rules
_STRING_SCAN_CHUNK = 1_000_000  # scan slices inside long minified printable runs
_STRINGS_RE = re.compile(rb"[\x20-\x7e]{4,}")

_HIGH_ENTROPY = 7.2             # bits/byte; compressed/encrypted/packed content trends toward 8.0

# Known packer signatures (substring match). Packing is a judgment-free fact: it is
# common in benign software too, so this emits an atom and lets a lens decide.
_PACKER_SIGS = [
    (b"UPX!", "UPX"), (b"UPX0", "UPX"), (b"UPX1", "UPX"),
    (b"ASPack", "ASPack"), (b"MPRESS1", "MPRESS"), (b"MPRESS2", "MPRESS"),
    (b".themida", "Themida"), (b"PECompact", "PECompact"), (b"FSG!", "FSG"),
    (b"PEtite", "Petite"),
]

# Archive recursion caps (bounded against zip bombs; never executes members).
_ARCHIVE_MAX_MEMBERS = 200
_ARCHIVE_MAX_MEMBER_BYTES = 2_000_000
_ARCHIVE_MAX_TOTAL = 24_000_000

_MANAGED_EXTS = {".jar", ".war", ".ear", ".class", ".dex", ".apk", ".aab",
                 ".pyc", ".pyo", ".wasm"}
_ARCHIVE_EXTS = {".zip", ".whl", ".egg", ".asar"}
_NATIVE_EXTS = {".so", ".dylib", ".dll", ".node", ".pyd", ".exe",
                ".o", ".a", ".bin", ".out"}

_SOURCE_EXTS = {
    ext for ext, lang in LANG_BY_EXT.items()
    if lang not in {"json", "toml", "config", "yaml", "xml", "html",
                    "markdown", "text", "csv", "hcl", "sql"}
}

_ASAR_MEMBER_EXTS = set(LANG_BY_EXT) | {
    ".css", ".scss", ".mdx", ".mts", ".cts", ".jsx", ".map",
}

_DECOMPILERS = {
    "managed": [
        ("jadx", "Android DEX/APK/AAB"),
        ("cfr", "JVM class/JAR"),
        ("procyon", "JVM class/JAR"),
        ("ilspycmd", ".NET assemblies"),
        ("uncompyle6", "Python bytecode"),
        ("decompyle3", "Python bytecode"),
        ("wasm2wat", "WebAssembly lift"),
    ],
    "native": [
        ("analyzeHeadless", "Ghidra headless"),
        ("ghidra", "Ghidra"),
        ("retdec-decompiler", "RetDec"),
        ("r2", "radare2"),
        ("radare2", "radare2"),
    ],
}


def decompiler_catalog() -> dict:
    """Stable provider names the binary-depth contract knows how to status-check."""
    return {
        kind: [{"name": name, "role": role} for name, role in providers]
        for kind, providers in _DECOMPILERS.items()
    }


def _detect(head: bytes, ext: str) -> str:
    for magic, label in _MAGIC:
        if head.startswith(magic):
            return label
    return BINARY_EXTS.get(ext, "binary artifact")


def extract_strings(data: bytes, limit: int = _MAX_STRINGS_TEXT) -> str:
    """`strings`-style extraction of printable ASCII runs (length >= 4)."""
    parts, total = [], 0
    for m in _STRINGS_RE.finditer(data):
        s = m.group(0).decode("ascii", "replace")
        parts.append(s)
        total += len(s) + 1
        if total >= limit:
            break
    return "\n".join(parts)


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte (0.0 to 8.0). High values indicate compressed,
    encrypted, or packed content."""
    if not data:
        return 0.0
    counts = collections.Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _detect_packer(data: bytes):
    for sig, name in _PACKER_SIGS:
        if sig in data:
            return name
    return None


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _sample_file(path: str, total_size: int) -> tuple[bytes, int, list[dict], list[tuple[int, bytes]]]:
    """Return bounded bytes for strings/structure triage.

    Large standalone executables often append bundled application code after the
    native runtime, so prefix-only or tail-only scanning can miss the payload.
    Keep analysis bounded while spreading windows across the artifact.
    """
    with open(path, "rb") as fh:
        if total_size <= _MAX_BYTES * _MAX_SAMPLE_WINDOWS:
            data = fh.read()
            return data, len(data), [{"offset": 0, "bytes": len(data)}], [(0, data)]
        max_offset = max(total_size - _MAX_BYTES, 0)
        offsets = {0}

        # Bun/pkg-style standalone executables append application code near the
        # suffix. Read that suffix contiguously, not as one tiny tail sample.
        tail_windows = min(_MAX_TAIL_WINDOWS, max(_MAX_SAMPLE_WINDOWS - 1, 0))
        tail_start = max(total_size - (_MAX_BYTES * tail_windows), 0)
        for i in range(tail_windows):
            offsets.add(min(tail_start + i * _MAX_BYTES, max_offset))

        remaining = max(_MAX_SAMPLE_WINDOWS - len(offsets), 0)
        if remaining and tail_start > _MAX_BYTES:
            max_middle_offset = max(tail_start - _MAX_BYTES, 0)
            for i in range(1, remaining + 1):
                offsets.add(round(i * max_middle_offset / (remaining + 1)))

        chunks = []
        regions = []
        for offset in sorted(offsets):
            fh.seek(offset)
            chunk = fh.read(_MAX_BYTES)
            if not chunk:
                continue
            chunks.append(chunk)
            regions.append({"offset": offset, "bytes": len(chunk)})
    data = b"\n".join(chunks)
    return data, sum(r["bytes"] for r in regions), regions, [
        (r["offset"], chunk) for r, chunk in zip(regions, chunks)
    ]


def _scan_sampled_strings(samples: list[tuple[int, bytes]], relpath: str) -> list:
    """Run content rules over bounded slices from each sampled binary window.

    A Bun/pkg-style executable can contain one huge printable minified JS run.
    A single capped `strings` view tends to keep the beginning of that run and
    miss code in the middle, so scan fixed-size string slices instead.
    """
    obs = []
    seen = set()
    for sample_offset, chunk in samples:
        for start in range(0, len(chunk), _STRING_SCAN_CHUNK):
            part = chunk[start:start + _STRING_SCAN_CHUNK]
            if not part:
                continue
            text = extract_strings(part, limit=_STRING_SCAN_CHUNK)
            if not text:
                continue
            offset = sample_offset + start
            for o in scan_strings(text, relpath, method="binary-strings", conf_factor=0.7):
                key = (o.atom, o.matched_text, o.rule_id)
                if key in seen:
                    continue
                seen.add(key)
                o.summary = f"{o.summary} (sample offset {offset})"
                obs.append(o)
    return obs


def _is_zip(data: bytes) -> bool:
    return data[:4] == b"PK\x03\x04"


def _is_asar(ext: str) -> bool:
    return ext == ".asar"


def _decompilation_kind(fmt: str, ext: str) -> str:
    low = (fmt or "").lower()
    if ext in _MANAGED_EXTS or any(s in low for s in (
            "java", "android", "python bytecode", "webassembly")):
        return "managed"
    if ext in _ARCHIVE_EXTS or "zip" in low:
        return "archive"
    if ext in _NATIVE_EXTS or any(s in low for s in (
            "elf", "pe binary", "mach-o", "native", "static archive")):
        return "native"
    return "unknown"


def _provider_status(kind: str) -> list:
    out = []
    for name, role in _DECOMPILERS.get(kind, []):
        path = shutil.which(name)
        out.append({
            "name": name,
            "role": role,
            "available": bool(path),
            "path": path,
        })
    return out


def decompilation_status(fmt: str, ext: str) -> dict:
    """Return opt-in decompilation provider metadata for an artifact.

    This only checks whether common tools are present on PATH. It never invokes a
    decompiler and never executes target bytes.
    """
    kind = _decompilation_kind(fmt, ext)
    if kind in ("managed", "native"):
        providers = _provider_status(kind)
        available = any(p["available"] for p in providers)
        return {
            "kind": kind,
            "status": "available-opt-in-not-run" if available else "providers-missing",
            "ran": False,
            "providers": providers,
            "note": ("Provider availability only. No decompiler was run during the scan; "
                     "decompilation remains an explicit opt-in review step."),
        }
    return {
        "kind": kind,
        "status": "not-applicable" if kind == "archive" else "unsupported-format",
        "ran": False,
        "providers": [],
        "note": ("No decompiler was run. Source-like container members re-enter the source "
                 "scan when the engine transform supports the format; remaining archive bytes "
                 "stay at inventory/string depth."),
    }


def _analysis_depth(fmt: str, ext: str, is_archive: bool, has_imports: bool,
                    member_strings: bool = False, source_container: bool = False,
                    binary_strings: bool = True) -> dict:
    methods = ["binary-inventory", "sha256"]
    if binary_strings:
        methods.append("binary-strings")
    methods.append("binary-structure")
    if is_archive and member_strings:
        methods.append("archive-member-strings")
    if source_container:
        methods.append("source-container-transform")
    if has_imports:
        methods.append("binary-imports")
    if source_container:
        base = "inventory-source-container-structure"
    elif binary_strings:
        base = "inventory-strings-structure"
    else:
        base = "inventory-structure"
    return {
        "status": f"{base}-imports-only" if has_imports else f"{base}-only",
        "defaultMethods": methods,
        "neverExecuted": True,
        "decompiled": False,
        "dynamic": False,
        "limitations": [
            "No target code execution.",
            "No managed/native decompilation in the default scan.",
            "Import-table capabilities show available APIs, not proven behavior.",
            "Supported source-container members are parsed by the normal source pipeline.",
        ],
    }


def _import_capabilities(cap_obs: list) -> list:
    return sorted({o.atom for o in cap_obs})


def _recurse_zip(data: bytes, relpath: str):
    """Triage members of a ZIP-family archive (JAR/APK/wheel/ZIP) through the same
    content rules. Returns (member_observations, member_count, note). Read-only and
    bounded: caps member count, per-member bytes, and total extracted bytes."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        names = [n for n in zf.namelist() if not n.endswith("/")]
    except Exception:
        return [], 0, "archive unreadable"

    obs, members, total = [], 0, 0
    truncated = len(names) > _ARCHIVE_MAX_MEMBERS
    for name in names[:_ARCHIVE_MAX_MEMBERS]:
        if total >= _ARCHIVE_MAX_TOTAL:
            truncated = True
            break
        try:
            if zf.getinfo(name).file_size > _ARCHIVE_MAX_MEMBER_BYTES * 8:
                continue  # skip absurd declared sizes without decompressing
            with zf.open(name) as fh:
                mdata = fh.read(_ARCHIVE_MAX_MEMBER_BYTES)
        except Exception:
            continue
        members += 1
        total += len(mdata)
        obs += scan_strings(extract_strings(mdata), f"{relpath}!{name}",
                            method="binary-strings", conf_factor=0.6)
    note = f"truncated at {_ARCHIVE_MAX_MEMBERS} members" if truncated else None
    return obs, members, note


def _file_size(fh) -> int:
    pos = fh.tell()
    fh.seek(0, os.SEEK_END)
    size = fh.tell()
    fh.seek(pos)
    return size


def _read_asar_header(fh) -> tuple[dict | None, int, str | None]:
    try:
        fh.seek(0)
        archive_size = _file_size(fh)
        raw = fh.read(8)
        if len(raw) < 8:
            return None, 0, "ASAR header truncated"
        payload_size, header_section_size = struct.unpack("<II", raw)
        if payload_size != 4:
            return None, 0, "ASAR size pickle unsupported"
        if header_section_size <= 8 or header_section_size > min(_ARCHIVE_MAX_TOTAL, archive_size - 8):
            return None, 0, "ASAR header size unsupported"
        header_buf = fh.read(header_section_size)
        if len(header_buf) != header_section_size or len(header_buf) < 8:
            return None, 0, "ASAR header truncated"
        header_payload_size = struct.unpack("<I", header_buf[:4])[0]
        header_json_size = struct.unpack("<i", header_buf[4:8])[0]
        if header_json_size <= 0 or header_payload_size > len(header_buf) - 4:
            return None, 0, "ASAR header size unsupported"
        if 8 + header_json_size > len(header_buf):
            return None, 0, "ASAR header JSON truncated"
        header = json.loads(header_buf[8:8 + header_json_size].decode("utf-8"))
        return header, 8 + header_section_size, None
    except Exception:
        return None, 0, "ASAR header unreadable"


def _asar_member_span(meta: dict, payload_start: int, archive_size: int) -> tuple[int, int] | None:
    offset_value = meta.get("offset")
    if not isinstance(offset_value, str) or not offset_value.isdigit():
        return None
    try:
        offset = int(offset_value)
        size = int(meta.get("size"))
    except Exception:
        return None
    if offset < 0 or size <= 0 or size > _ARCHIVE_MAX_MEMBER_BYTES * 8:
        return None
    absolute = payload_start + offset
    if absolute < payload_start or absolute + size > archive_size:
        return None
    return offset, size


def _iter_asar_files(node: dict, prefix: str = ""):
    for name, meta in (node.get("files") or {}).items():
        rel = posixpath.join(prefix, name) if prefix else name
        if "files" in meta:
            yield from _iter_asar_files(meta, rel)
        else:
            yield rel, meta


def _asar_member_priority(item: tuple[str, dict]) -> tuple:
    name, _ = item
    ext = posixpath.splitext(name)[1].lower()
    vendor = name.startswith("node_modules/") or "/node_modules/" in name
    if name == "package.json":
        group = 0
    elif name.startswith(("out/main/", "out/host/", "out/preload/", "out/metadata/")):
        group = 1
    elif name.startswith("out/renderer/") and "/assets/" not in name:
        group = 2
    elif name.startswith("out/"):
        group = 3
    elif not vendor:
        group = 4
    else:
        group = 5
    return (group, vendor, ext not in _ASAR_MEMBER_EXTS, len(name), name)


def _looks_like_textmate_grammar_member(name: str, data: bytes) -> bool:
    """Bundled syntax grammars are vocabularies, not behavior.

    Electron apps often ship minified ESM chunks that export TextMate grammar JSON
    via `Object.freeze(JSON.parse(...))`. Those files intentionally contain long
    command lists (`ipconfig`, `net user`, `schtasks`, ...), which are excellent
    highlighting data and terrible malicious-code evidence.
    """
    ext = posixpath.splitext(name)[1].lower()
    if ext not in {".js", ".mjs", ".cjs", ".json"}:
        return False
    head = data[:200_000]
    return (
        b'"scopeName":"source.' in head
        and b'"patterns":' in head
        and b'"repository":' in head
        and (b"JSON.parse(`" in head or ext == ".json")
    )


def _recurse_asar(abspath: str, relpath: str):
    """Count Electron ASAR source members without downgrading them to strings.

    The engine's source-container transform feeds extractable source members back
    into the normal source scan. Binary triage keeps the archive structure fact
    here and avoids duplicate `binary-strings` observations for those members.
    """
    try:
        with open(abspath, "rb") as fh:
            header, payload_start, error = _read_asar_header(fh)
            if error or not header:
                return [], 0, error or "ASAR header unreadable"
            archive_size = _file_size(fh)
            candidates = []
            for name, meta in _iter_asar_files(header):
                ext = posixpath.splitext(name)[1].lower()
                if meta.get("unpacked") or ext not in LANG_BY_EXT:
                    continue
                if _asar_member_span(meta, payload_start, archive_size) is None:
                    continue
                candidates.append((name, meta))
            candidates.sort(key=_asar_member_priority)

            obs, members, total = [], 0, 0
            truncated = len(candidates) > _ARCHIVE_MAX_MEMBERS
            skipped_grammars = 0
            for name, meta in candidates[:_ARCHIVE_MAX_MEMBERS]:
                if total >= _ARCHIVE_MAX_TOTAL:
                    truncated = True
                    break
                try:
                    span = _asar_member_span(meta, payload_start, archive_size)
                    if span is None:
                        continue
                    offset, declared_size = span
                    size = min(declared_size, _ARCHIVE_MAX_MEMBER_BYTES)
                    fh.seek(payload_start + offset)
                    mdata = fh.read(size)
                except Exception:
                    continue
                total += len(mdata)
                if _looks_like_textmate_grammar_member(name, mdata):
                    skipped_grammars += 1
                    continue
                members += 1
            notes = []
            if truncated:
                notes.append(f"truncated at {_ARCHIVE_MAX_MEMBERS} ASAR members")
            if skipped_grammars:
                notes.append(f"skipped {skipped_grammars} syntax grammar member(s)")
            note = "; ".join(notes) if notes else None
            return obs, members, note
    except Exception:
        return [], 0, "ASAR archive unreadable"


def _nearby_source_context(root: str, relpath: str) -> tuple[list, list]:
    root_abs = os.path.realpath(root)
    art_abs = os.path.realpath(os.path.join(root_abs, relpath))
    cur = os.path.dirname(art_abs)
    sources, manifests, seen = [], [], set()

    while cur.startswith(root_abs):
        try:
            names = sorted(os.listdir(cur))
        except Exception:
            break
        for name in names:
            p = os.path.join(cur, name)
            if not os.path.isfile(p) or p == art_abs:
                continue
            r = os.path.relpath(p, root_abs)
            if r in seen:
                continue
            seen.add(r)
            ext = os.path.splitext(name)[1].lower()
            if name in MANIFEST_NAMES:
                manifests.append(r)
            elif ext in _SOURCE_EXTS:
                sources.append(r)
        if cur == root_abs:
            break
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    return sources[:20], manifests[:20]


def annotate_source_drift(binaries: list, observations: list, root: str) -> None:
    """Attach deterministic source-to-binary drift scaffolding to artifacts.

    This is intentionally conservative metadata: local source/manifests near the
    artifact and project-level binary-import capabilities not also seen in source
    observations. It does not rebuild, diff behavior, or execute/decompile code.
    """
    source_atoms = {
        o.get("atom") for o in observations
        if not (o.get("method") or "").startswith("binary-")
    }
    for b in binaries:
        if b.get("error"):
            continue
        kind = (b.get("decompilation") or {}).get("kind") or "unknown"
        sources, manifests = _nearby_source_context(root, b.get("path", ""))
        caps = set(b.get("importCapabilities") or [])
        binary_only = sorted(a for a in caps if a not in source_atoms)
        indicators = []
        if kind in ("native", "managed") and not sources and not manifests:
            indicators.append("binary-without-nearby-source")
        if kind == "native" and (sources or manifests):
            indicators.append("native-artifact-near-source-package")
        if kind == "managed" and (sources or manifests):
            indicators.append("managed-artifact-near-source-package")
        if binary_only:
            indicators.append("binary-import-capability-not-seen-in-source")
        b["sourceDrift"] = {
            "status": "scaffold-only",
            "indicators": indicators,
            "nearbySourceFiles": sources,
            "nearbyManifests": manifests,
            "binaryOnlyImportCapabilities": binary_only,
            "note": ("Deterministic local indicators only: no rebuild, provenance proof, "
                     "decompilation, or behavioral source-to-binary diff was performed."),
        }


def triage(abspath: str, relpath: str, ext: str, source_container: bool = False) -> tuple:
    """Return (artifact_dict, observations). Hashes the artifact, identifies the
    format, measures entropy, looks for packers, recurses ZIP-family archives, and
    runs the content rules over extracted strings. Never executes."""
    try:
        total_size = os.path.getsize(abspath)
        data, scanned, sample_regions, samples = _sample_file(abspath, total_size)
        with open(abspath, "rb") as fh:
            head = fh.read(64)
        full_sha256 = _sha256_file(abspath)
    except Exception as e:
        return ({"path": relpath, "format": "unreadable", "error": str(e)[:120]}, [])

    fmt = _detect(head, ext)
    is_zip = _is_zip(data)
    is_asar = _is_asar(ext)
    is_archive = is_zip or is_asar
    entropy = shannon_entropy(data)

    # string-derived observations (content hits), top-level then archive members
    string_obs = [] if is_asar else _scan_sampled_strings(samples, relpath)
    # structure observations (judgment-free facts: entropy / packer / archive)
    struct_obs = []

    art = {
        "path": relpath,
        "format": fmt,
        "sha256": full_sha256,
        "bytes": total_size,
        "scanned": scanned,
        "truncated": total_size > scanned,
        "sampleRegions": sample_regions,
        "entropy": round(entropy, 2),
    }

    # Archives are compressed/containerized by nature, so high entropy there is expected, not a signal.
    if entropy >= _HIGH_ENTROPY and not is_archive:
        struct_obs.append(Observation(
            atom="BIN.HIGH_ENTROPY", method="binary-structure", confidence=0.6,
            path=relpath, rule_id="binary.entropy",
            summary=f"high Shannon entropy ({entropy:.2f}/8.0): content is compressed, "
                    "encrypted, or packed"))

    packer = _detect_packer(data)
    if packer:
        art["packer"] = packer
        struct_obs.append(Observation(
            atom="BIN.PACKER", method="binary-structure", confidence=0.8,
            path=relpath, rule_id="binary.packer",
            summary=f"{packer} packer signature present"))

    if is_zip:
        members_obs, member_count, note = _recurse_zip(data, relpath)
        art["archive"] = True
        art["members"] = member_count
        string_obs += members_obs
        if member_count:
            struct_obs.append(Observation(
                atom="BIN.ARCHIVE", method="binary-structure", confidence=0.9,
                path=relpath, rule_id="binary.archive",
                summary=f"ZIP-family archive expanded: {member_count} member(s) triaged"
                        + (f" ({note})" if note else "")))
    elif is_asar:
        members_obs, member_count, note = _recurse_asar(abspath, relpath)
        art["archive"] = True
        art["members"] = member_count
        string_obs += members_obs
        if member_count:
            struct_obs.append(Observation(
                atom="BIN.ARCHIVE", method="binary-structure", confidence=0.9,
                path=relpath, rule_id="binary.archive",
                summary=f"Electron ASAR archive expanded: {member_count} member(s) triaged"
                        + (f" ({note})" if note else "")))

    # capability inference from import / symbol tables (ELF / PE / Mach-O); native
    # formats only (archives return nothing here, their members are triaged above)
    imports, libraries, cap_obs = analyze_caps(data[:_MAX_BYTES], relpath)
    if imports:
        art["imports"] = imports[:200]
    if libraries:
        art["libraries"] = libraries[:50]
    art["importCapabilities"] = _import_capabilities(cap_obs)
    struct_obs += cap_obs

    art["analysisDepth"] = _analysis_depth(
        fmt, ext, is_archive, bool(imports or cap_obs),
        member_strings=is_zip, source_container=source_container, binary_strings=not is_asar)
    art["decompilation"] = decompilation_status(fmt, ext)
    art["stringObservations"] = len(string_obs)
    return (art, string_obs + struct_obs)

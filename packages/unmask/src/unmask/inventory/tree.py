"""Bounded target tree + kind classification.

Internal generator (no dependency on the external `tree` command). High-volume
directories are collapsed unless explicitly expanded, and output is capped by
depth and entry count so a tree never bloats a report or a prompt.

Kind classification is shallow — extension first, with a content-magic sniff for the
binaries a filename doesn't advertise (an extensionless executable like a Bun/pkg
single-file CLI, or a binary hiding under a benign suffix). It exists so the graph can
spot binary artifacts and route them through the RE plugin boundary, not to replace the
scanner's own inventory.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

_COLLAPSE_DIRS = {
    "node_modules", ".git", ".hg", ".svn", "dist", "build", "out",
    ".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", ".gradle", "target", "vendor", ".next", ".turbo",
    ".idea", ".DS_Store",
}

_MANIFESTS = {
    "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
    "pyproject.toml", "setup.py", "setup.cfg", "requirements.txt", "Pipfile",
    "Cargo.toml", "go.mod", "pom.xml", "build.gradle", "Gemfile", "composer.json",
}
_SOURCE_EXT = {
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".rb", ".go", ".rs",
    ".java", ".kt", ".c", ".cc", ".cpp", ".h", ".hpp", ".cs", ".php", ".sh",
    ".ps1", ".pl", ".lua", ".swift", ".scala", ".clj",
}
_ARCHIVE_EXT = {".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".asar", ".whl", ".egg"}
_NATIVE_EXT = {".so", ".dylib", ".dll", ".o", ".a", ".bin", ".elf", ".exe"}
_DOTNET_EXT = {".dll", ".exe"}  # ambiguous; magic would refine
_JVM_EXT = {".jar", ".class", ".dex", ".apk", ".aar"}

# Content magic for binaries/archives a filename may not advertise. Authoritative over a
# non-binary extension: an extensionless executable, or a binary masquerading under a
# source/text suffix, must still reach the RE path — trusting the extension is itself a
# weakness for a malicious-code detector.
_BINARY_MAGIC: tuple[tuple[bytes, str], ...] = (
    (b"\x7fELF", "native-binary"),           # ELF (Linux/BSD; incl. Bun/pkg single-file CLIs)
    (b"MZ", "native-binary"),                # PE / DOS (Windows exe/dll)
    (b"\xfe\xed\xfa\xce", "native-binary"),  # Mach-O 32-bit
    (b"\xfe\xed\xfa\xcf", "native-binary"),  # Mach-O 64-bit
    (b"\xce\xfa\xed\xfe", "native-binary"),  # Mach-O 32-bit (byte-swapped)
    (b"\xcf\xfa\xed\xfe", "native-binary"),  # Mach-O 64-bit (byte-swapped)
    (b"PK\x03\x04", "archive"),              # zip family (jar/apk/asar/whl/…)
    (b"PK\x05\x06", "archive"),              # empty zip
    (b"\x1f\x8b", "archive"),                # gzip
    (b"7z\xbc\xaf\x27\x1c", "archive"),      # 7-zip
    (b"\xfd7zXZ\x00", "archive"),            # xz
    (b"\x28\xb5\x2f\xfd", "archive"),        # zstd
)


def _sniff_magic(path: Path) -> str | None:
    """A binary/archive kind from the file's leading bytes, or None. Best-effort: an
    unreadable or non-existent path (e.g. a bare relative label) yields None."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(8)
    except OSError:
        return None
    for sig, kind in _BINARY_MAGIC:
        if head.startswith(sig):
            return kind
    return None


def classify_kind(path: Path) -> str:
    name = path.name
    ext = path.suffix.lower()
    if name in _MANIFESTS:
        return "manifest"
    # Explicit binary/bytecode/archive extensions keep their precise kind (trusted).
    if ext in _JVM_EXT:
        return {"jar": "jar", "apk": "apk", "dex": "dex"}.get(ext.lstrip("."), "jvm-bytecode")
    if ext in {".pyc", ".pyo"}:
        return "pyc"
    if ext in _ARCHIVE_EXT:
        return "archive"
    if ext in _NATIVE_EXT:
        return "native-binary"
    # No binary extension: content magic is authoritative — catches the extensionless
    # executable and the binary hiding under a benign suffix that extension-only misses.
    sniffed = _sniff_magic(path)
    if sniffed:
        return sniffed
    if ext in _SOURCE_EXT:
        return "source-file"
    if ext in {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".md", ".txt"}:
        return "text"
    return "other"


# Kinds that need the RE plugin to be meaningfully analysed.
BINARY_KINDS = {"native-binary", "jar", "apk", "dex", "jvm-bytecode", "archive", "pyc"}


@dataclass
class TreeResult:
    text: str
    json: dict
    summary: dict
    binary_paths: list[str] = field(default_factory=list)


def build_tree(root: str | Path, *, max_depth: int = 4, max_entries: int = 2000,
               include_hidden: bool = False) -> TreeResult:
    root = Path(root).resolve()
    lines: list[str] = [root.name or str(root)]
    files = dirs = 0
    truncated = False
    binary_paths: list[str] = []
    largest: list[tuple[int, str]] = []
    entries = 0

    def walk(d: Path, depth: int, prefix: str) -> None:
        nonlocal files, dirs, truncated, entries
        if depth > max_depth:
            return
        try:
            children = sorted(d.iterdir(), key=lambda p: (p.is_file(), p.name.lower()))
        except (PermissionError, OSError):
            return
        for child in children:
            if not include_hidden and child.name.startswith("."):
                continue
            if entries >= max_entries:
                truncated = True
                return
            entries += 1
            connector = "|-- "
            if child.is_dir():
                dirs += 1
                if child.name in _COLLAPSE_DIRS:
                    lines.append(f"{prefix}{connector}{child.name}/  (collapsed)")
                    continue
                lines.append(f"{prefix}{connector}{child.name}/")
                walk(child, depth + 1, prefix + "|   ")
            else:
                files += 1
                kind = classify_kind(child)
                tag = f"  [{kind}]" if kind in BINARY_KINDS else ""
                lines.append(f"{prefix}{connector}{child.name}{tag}")
                if kind in BINARY_KINDS:
                    binary_paths.append(str(child.relative_to(root)))
                try:
                    largest.append((child.stat().st_size, str(child.relative_to(root))))
                except OSError:
                    pass

    if root.is_dir():
        walk(root, 1, "")
    else:  # single-file target
        files = 1
        lines.append(f"|-- {root.name}")
        if classify_kind(root) in BINARY_KINDS:
            binary_paths.append(root.name)

    largest.sort(reverse=True)
    summary = {
        "files": files,
        "directories": dirs,
        "truncated": truncated,
        "largestFiles": [{"path": p, "bytes": s} for s, p in largest[:5]],
        "binaryArtifacts": len(binary_paths),
    }
    return TreeResult(
        text="\n".join(lines),
        json={
            "root": str(root),
            "policy": {"maxDepth": max_depth, "maxEntries": max_entries,
                       "includeHidden": include_hidden},
            "summary": summary,
        },
        summary=summary,
        binary_paths=binary_paths,
    )

"""Stage 1: Inventory. Walk a target, classify files, detect ecosystems,
read an optional `parallax.json` capability declaration, and extract the
project's stated purpose (used by the curiosity lens)."""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build",
    ".ordna", ".idea", ".mypy_cache", ".pytest_cache", ".tox", "site-packages",
}

LANG_BY_EXT = {
    # JS / TS family
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".jsx": "javascript", ".ts": "typescript", ".tsx": "tsx",
    ".mts": "typescript", ".cts": "typescript",
    # Python
    ".py": "python", ".pyi": "python", ".pyw": "python",
    # Go / Rust (modern, requested)
    ".go": "go",
    ".rs": "rust",
    # C / C++ / Objective-C
    ".c": "c",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".c++": "cpp",
    ".h": "cpp", ".hpp": "cpp", ".hh": "cpp", ".hxx": "cpp", ".inl": "cpp",
    ".m": "objc", ".mm": "objc",
    # JVM / .NET
    ".java": "java",
    ".cs": "csharp",
    ".kt": "kotlin", ".kts": "kotlin",
    ".scala": "scala", ".sc": "scala",
    ".groovy": "groovy", ".gradle": "groovy",
    # Scripting
    ".rb": "ruby", ".erb": "ruby", ".gemspec": "ruby", ".rake": "ruby",
    ".php": "php", ".phtml": "php",
    ".pl": "perl", ".pm": "perl", ".t": "perl",
    ".lua": "lua",
    ".r": "r",
    ".swift": "swift",
    ".hs": "haskell",
    ".ex": "elixir", ".exs": "elixir",
    # Visual Basic / VBScript
    ".vb": "vb", ".vbs": "vb",
    # Shell / Windows scripting
    ".sh": "shell", ".bash": "shell", ".zsh": "shell", ".ksh": "shell",
    ".ps1": "powershell", ".psm1": "powershell", ".psd1": "powershell",
    ".bat": "batch", ".cmd": "batch",
    ".applescript": "applescript",
    # Data / config / IaC
    ".sql": "sql",
    ".tf": "hcl", ".hcl": "hcl", ".tfvars": "hcl",
    ".json": "json", ".toml": "toml", ".cfg": "config", ".ini": "config",
    ".conf": "config", ".env": "config",
    ".yml": "yaml", ".yaml": "yaml", ".xml": "xml", ".html": "html",
    ".hbs": "text", ".csv": "text", ".md": "markdown", ".txt": "text",
}

# Compiled / binary artifacts: extension -> human-readable format label. These
# are not parsed as source; they go through the binary triage path (hash +
# strings + content rules), with deep behavior declared as a blind spot.
BINARY_EXTS = {
    ".so": "native shared library", ".dylib": "native shared library",
    ".dll": "native shared library (PE)", ".node": "native Node addon",
    ".pyd": "native Python extension (PE)", ".exe": "PE executable",
    ".o": "native object file", ".a": "native static archive",
    ".bin": "binary blob", ".out": "native executable",
    ".class": "Java class (bytecode)", ".jar": "Java archive",
    ".war": "Java web archive", ".ear": "Java archive",
    ".dex": "Android DEX", ".apk": "Android package", ".aab": "Android bundle",
    ".pyc": "Python bytecode", ".pyo": "Python bytecode",
    ".wasm": "WebAssembly module",
    ".whl": "Python wheel (archive)", ".egg": "Python egg (archive)",
    ".zip": "ZIP archive", ".asar": "Electron ASAR archive",
}

# Magic-byte signatures for extensionless or otherwise unknown compiled artifacts.
# The deeper binary triage module has the full format labeling; inventory only
# needs enough to route files into that safe, read-only path.
BINARY_MAGIC = (
    b"\x7fELF",          # ELF
    b"MZ",               # PE
    b"\xfe\xed\xfa\xce", # Mach-O
    b"\xfe\xed\xfa\xcf", # Mach-O 64-bit
    b"\xcf\xfa\xed\xfe", # Mach-O 64-bit
    b"\xce\xfa\xed\xfe", # Mach-O
    b"\xca\xfe\xba\xbe", # Java class or Mach-O fat binary
    b"dex\n",            # Android DEX
    b"\x00asm",          # WebAssembly
    b"PK\x03\x04",       # ZIP / JAR / archive
    b"!<arch>",          # static archive
    b"\xed\xab\xee\xdb", # RPM
)

# Files with no extension that we still classify by name.
LANG_BY_NAME = {
    "Dockerfile": "dockerfile", "Containerfile": "dockerfile",
    "Makefile": "make", "Gemfile": "ruby", "Rakefile": "ruby",
    "build.rs": "rust",
}

MANIFEST_NAMES = {
    "package.json", "setup.py", "pyproject.toml", "requirements.txt",
    "Cargo.toml", "go.mod", "composer.json", "Gemfile", "build.gradle",
    "pom.xml", "build.rs",
}


# Manifest file name -> package ecosystem (one row per real registry).
_ECOSYSTEM_BY_NAME = {
    "package.json": "npm",
    "setup.py": "pypi", "pyproject.toml": "pypi", "requirements.txt": "pypi",
    "Cargo.toml": "cargo", "build.rs": "cargo",
    "go.mod": "go",
    "composer.json": "composer",
    "Gemfile": "rubygems", "Rakefile": "rubygems",
    "pom.xml": "maven", "build.gradle": "gradle",
}


@dataclass
class FileEntry:
    abspath: str
    relpath: str
    lang: str
    name: str


@dataclass
class Inventory:
    root: str
    files: list = field(default_factory=list)
    ecosystems: set = field(default_factory=set)
    expected_capabilities: list = field(default_factory=list)
    purpose: str = ""
    binaries: list = field(default_factory=list)  # binary triage artifacts
    dataflow: dict = field(default_factory=dict)  # {relpath: [proven dataflow paths]}
    reachability: dict = field(default_factory=dict)  # cross-file call-graph reachability
    artifact_transforms: list = field(default_factory=list)
    _artifact_tempdirs: list = field(default_factory=list, repr=False)

    def source_files(self):
        return [f for f in self.files if f.lang in ("javascript", "python", "shell")]


def _target_file(root: str, name: str) -> str | None:
    if os.path.isfile(root):
        return root if os.path.basename(root) == name else None
    return os.path.join(root, name)


def _read_declaration(root: str, inv: "Inventory") -> None:
    """Optional developer annotation: parallax.json { expectedCapabilities: [...] }."""
    pj = _target_file(root, "parallax.json")
    if not pj:
        return
    if not os.path.isfile(pj):
        return
    try:
        with open(pj, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        ec = data.get("expectedCapabilities")
        if isinstance(ec, list):
            inv.expected_capabilities = [str(x) for x in ec]
    except Exception:
        pass


def _read_purpose(root: str, inv: "Inventory") -> None:
    """Best-effort stated purpose from manifests + README. Lowercased text the
    curiosity lens compares behavior against."""
    bits = []

    def _json_desc(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                d = json.load(fh)
            for k in ("description", "name"):
                if isinstance(d.get(k), str):
                    bits.append(d[k])
        except Exception:
            pass

    for nm in ("package.json", "mcp.json", "server.json"):
        p = _target_file(root, nm)
        if p and os.path.isfile(p):
            _json_desc(p)

    pp = _target_file(root, "pyproject.toml")
    if pp and os.path.isfile(pp):
        try:
            import tomllib
            with open(pp, "rb") as fh:
                proj = (tomllib.load(fh).get("project") or {})
            for k in ("description", "name"):
                if isinstance(proj.get(k), str):
                    bits.append(proj[k])
        except Exception:
            pass

    if os.path.isdir(root):
        for rn in ("README.md", "readme.md", "README"):
            rp = os.path.join(root, rn)
            if os.path.isfile(rp):
                try:
                    with open(rp, "r", encoding="utf-8") as fh:
                        for line in fh:
                            s = line.strip().lstrip("#").strip()
                            if s:
                                bits.append(s)
                                break
                except Exception:
                    pass
                break

    inv.purpose = " ".join(bits).lower()


def _add_file(inv: Inventory, rel_root: str, ab: str) -> None:
    name = os.path.basename(ab)
    rel = os.path.relpath(ab, rel_root)
    ext = os.path.splitext(name)[1].lower()
    lang = (LANG_BY_NAME.get(name)
            or ("binary" if ext in BINARY_EXTS else None)
            or LANG_BY_EXT.get(ext))
    if lang is None:
        try:
            with open(ab, "rb") as fh:
                head = fh.read(8)
            if any(head.startswith(magic) for magic in BINARY_MAGIC):
                lang = "binary"
        except Exception:
            pass
    lang = lang or "other"
    inv.files.append(FileEntry(abspath=ab, relpath=rel, lang=lang, name=name))
    eco = _ECOSYSTEM_BY_NAME.get(name)
    if eco:
        inv.ecosystems.add(eco)


def build(target: str) -> Inventory:
    target_path = Path(target).resolve()
    root = str(target_path)
    inv = Inventory(root=root)
    if os.path.isfile(root):
        _add_file(inv, str(target_path.parent), root)
        _read_declaration(root, inv)
        _read_purpose(root, inv)
        return inv
    if not os.path.isdir(root):
        print(f"prlx: warning: path is not a directory: {target}", file=sys.stderr)
        return inv
    for dirpath, dirnames, filenames in os.walk(root):
        # Skip dot-dirs and known noise, but keep .github so CI workflows are scanned.
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS
                       and (not d.startswith(".") or d == ".github")]
        for name in filenames:
            _add_file(inv, root, os.path.join(dirpath, name))
    _read_declaration(root, inv)
    _read_purpose(root, inv)
    return inv

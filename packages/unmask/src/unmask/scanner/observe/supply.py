"""Local supply-chain atoms → PKGM.UNDECLARED (phantom dependencies).

Algorithm-shaped (not signature data), ported from the reference `supply.analyze`.
A module imported but never declared in the manifest is unpinned — a squatter can
supply it. Ecosystem-scoped: stdlib is checked per ecosystem, so a python
`import json` inside an npm package is flagged (json isn't a node builtin) — this
is the reference behaviour, deliberately.

Stdlib name sets are taxonomy-owned reference data (`reference/standard-libraries`).
Typosquat detection (PKGM.TYPOSQUAT) is a separate supply detector, added when a
fixture exercises it — kept out until then rather than shipping untested code.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from unmask.scanner.observe.atoms import Observation
from unmask.scanner.observe.inventory import Inventory
from unmask.scanner.refdata import load_reference

_stdlib = load_reference("standard-libraries") or {}
PY_STDLIB = set(_stdlib.get("python") or [])
NODE_BUILTINS = set(_stdlib.get("node") or [])

_IMPORT_PY = re.compile(r"(?m)^\s*(?:import\s+([a-zA-Z0-9_]+)|from\s+([a-zA-Z0-9_]+)[\w.]*\s+import)")
_REQUIRE_JS = re.compile(r"""require\(\s*['"]([^'"]+)['"]\s*\)""")
_IMPORT_JS = re.compile(r"""(?:import\b[^'"]*from\s*|import\s*)['"]([^'"]+)['"]""")

_MANIFEST_ECO = {"package.json": "npm", "requirements.txt": "pypi",
                 "pyproject.toml": "pypi", "setup.py": "pypi", "Pipfile": "pypi"}
_PHANTOM_LANGS = {"python", "javascript", "typescript", "tsx"}
_MAX_PHANTOM = 25


def _norm(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def _name(f) -> str:
    return f.path.rsplit("/", 1)[-1]


def _read(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _ecosystems(inv: Inventory) -> set[str]:
    return {eco for f in inv.files if (eco := _MANIFEST_ECO.get(_name(f)))}


def _has_manifest(inv: Inventory) -> bool:
    return any(_name(f) in _MANIFEST_ECO for f in inv.files)


def _declared_deps(inv: Inventory) -> set[str]:
    deps: set[str] = set()
    for f in inv.files:
        name = _name(f)
        if name == "package.json":
            try:
                d = json.loads(_read(f.path))
            except (json.JSONDecodeError, ValueError):
                continue
            for k in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                if isinstance(d.get(k), dict):
                    deps |= {_norm(x) for x in d[k]}
        elif name == "requirements.txt":
            for line in _read(f.path).splitlines():
                if line.strip().startswith("#"):
                    continue
                m = re.match(r"\s*([A-Za-z0-9._-]+)", line)
                if m:
                    deps.add(_norm(m.group(1)))
        elif name == "pyproject.toml":
            for m in re.finditer(r"['\"]([A-Za-z0-9._-]+)\s*(?:[<>=!~\[ ].*)?['\"]", _read(f.path)):
                deps.add(_norm(m.group(1)))
        elif name == "setup.py":
            m = re.search(r"install_requires\s*=\s*\[(.*?)\]", _read(f.path), re.DOTALL)
            if m:
                for d in re.finditer(r"['\"]([A-Za-z0-9._-]+)\s*(?:[<>=!~\[ ].*)?['\"]", m.group(1)):
                    deps.add(_norm(d.group(1)))
    return deps


def _package_name(inv: Inventory) -> str:
    for f in inv.files:
        if _name(f) == "package.json":
            try:
                d = json.loads(_read(f.path))
                if isinstance(d.get("name"), str):
                    return d["name"]
            except (json.JSONDecodeError, ValueError):
                pass
    return os.path.basename(inv.root)


def _imports(text: str, lang: str) -> set[str]:
    out: set[str] = set()
    if lang == "python":
        for m in _IMPORT_PY.finditer(text):
            out.add(m.group(1) or m.group(2))
    else:
        for rx in (_REQUIRE_JS, _IMPORT_JS):
            for m in rx.finditer(text):
                spec = m.group(1)
                if spec.startswith(".") or spec.startswith("/"):
                    continue
                parts = spec.split("/")
                out.add("/".join(parts[:2]) if spec.startswith("@") else parts[0])
    return {x for x in out if x}


def _local_tops(inv: Inventory) -> set[str]:
    tops: set[str] = set()
    for f in inv.files:
        parts = f.rel.replace("\\", "/").split("/")
        if len(parts) > 1:
            tops.add(_norm(parts[0]))
        else:
            tops.add(_norm(os.path.splitext(parts[0])[0]))
    return tops


def observe_supply(inv: Inventory) -> list[Observation]:
    # A manifest present means the declared dependency set is meant to be complete;
    # without one, "undeclared" is meaningless.
    if not _has_manifest(inv):
        return []
    ecos = _ecosystems(inv)
    declared = _declared_deps(inv)
    stdlib = PY_STDLIB if "pypi" in ecos else NODE_BUILTINS
    self_name = _norm(_package_name(inv))
    local_tops = _local_tops(inv)

    out: list[Observation] = []
    seen: set[str] = set()
    for f in inv.files:
        if f.language not in _PHANTOM_LANGS:
            continue
        lang = "python" if f.language == "python" else "js"
        for mod in _imports(_read(f.path), lang):
            nm = _norm(mod)
            base = mod.split(".")[0] if lang == "python" else mod
            nbase = _norm(base)
            if (nm in declared or nbase in declared or base in stdlib or nm in stdlib
                    or nm in seen or nbase == self_name or nbase in local_tops):
                continue
            seen.add(nm)
            out.append(Observation(
                atom="PKGM.UNDECLARED", confidence=0.45, method="static-source",
                path=f.rel, line=1, rule_id="supply.undeclared", evidence=mod,
                summary=f"imports '{mod}' but it is not a declared dependency "
                        f"(unpinned resolution; a squatter can supply it)",
            ))
            if len(seen) >= _MAX_PHANTOM:
                return out
    return out

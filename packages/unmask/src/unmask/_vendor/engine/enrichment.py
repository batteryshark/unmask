"""Enrichment: external/contextual facts that modify confidence, never severity.

Enrichment is the taxonomy's third input alongside atoms and relationships. A fact
about the artifact's context (it runs at install time, it ships opaque native code,
it pulls an unpinned dependency) does not by itself say "malicious"; it amplifies or
attenuates confidence in findings that already exist. The taxonomy defines the data
points (ENR.<CATEGORY>.<NAME>) and the per-lens amplify/attenuate/neutral model.

This engine is static and offline by design, so it populates only the LOCALLY
derivable enrichment, deterministically, from observations it already makes. The
networked enrichment (registry age, ownership, downloads, WHOIS domain age, threat
intel) is a real part of the model but belongs to an online deployment: it is
expressed here as the `EnrichmentProvider` interface, not bundled. A static
analyzer maintaining live OSINT integrations would trade determinism and the 0-FP
reproducibility gate for facts it cannot fetch offline.

Discipline: enrichment NEVER creates or removes findings (recall and the
false-positive gate are unaffected); it only adjusts the confidence of findings
that are already present, by a stated, bounded rule.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Protocol

try:
    import tomllib
except Exception:  # pragma: no cover - Python <3.11 fallback is not bundled.
    tomllib = None

# how much one amplifying enrichment raises an applicable finding's confidence,
# and the ceiling no amount of enrichment can push a finding past.
_AMPLIFY_STEP = 0.1
_CONF_CEILING = 0.95
_MAX_DEP_EXAMPLES = 6
_SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build",
    ".tox", "site-packages",
}
_MANIFEST_NAMES = {
    "package.json", "requirements.txt", "pyproject.toml", "Pipfile",
    "Cargo.toml", "go.mod", "composer.json", "Gemfile",
}
_LOCKFILE_NAMES = {
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "poetry.lock", "uv.lock", "Pipfile.lock", "Cargo.lock", "go.sum",
    "composer.lock", "Gemfile.lock",
}
_DEFAULT_SOURCE_HOSTS = {
    "registry.npmjs.org", "pypi.org", "files.pythonhosted.org", "crates.io",
    "proxy.golang.org", "packagist.org", "repo.packagist.org", "rubygems.org",
}

_LOCAL_PROVIDER_ID = "local-static"
_LOCAL_PROVIDER_NAME = "Local static provider"
_LOCAL_TTL = "scan-snapshot"

# Every fact id the local providers can emit. The engine emits facts keyed only by
# their atom families (which is what the confidence math reads); a product that
# wants to say which of ITS compositions a fact touches passes a composition_map
# (fact id -> [composition ids]) to derive()/fact_catalog(). See prlx_mcd for the
# mcd mapping. Kept lens-neutral here so the engine owns no product content.
_LOCAL_FACT_IDS = [
    "ENR.EXEC.PHASE", "ENR.DEP.RESOLUTION", "ENR.DRIFT.NATIVE",
    "ENR.DEP.NO_LOCKFILE", "ENR.DEP.UNLOCKED", "ENR.DEP.LOCKED",
    "ENR.DEP.SOURCE", "ENR.PKG.UNPINNED", "ENR.PKG.UNKNOWN_VERSION",
]

_UNAVAILABLE_PROVIDER_STATUS = [
    {
        "id": "package-registry-osint",
        "name": "Package registry OSINT",
        "kind": "external",
        "availability": "unavailable",
        "observedAt": None,
        "ttl": "not-observed",
        "provides": [
            "ENR.PKG.AGE", "ENR.PKG.OWNER", "ENR.PKG.DOWNLOADS",
            "ENR.PKG.PROVENANCE",
        ],
        "unavailableReason": "offline engine: registry HTTP/API calls are intentionally not bundled",
    },
    {
        "id": "dns-whois-reputation",
        "name": "DNS/WHOIS/domain reputation",
        "kind": "external",
        "availability": "unavailable",
        "observedAt": None,
        "ttl": "not-observed",
        "provides": [
            "ENR.NET.DOMAIN_AGE", "ENR.NET.HOSTING",
            "ENR.NET.JURISDICTION", "ENR.NET.REPUTATION",
        ],
        "unavailableReason": "offline engine: DNS, WHOIS, and reputation lookups are intentionally not bundled",
    },
    {
        "id": "threat-intel",
        "name": "Threat-intelligence reputation",
        "kind": "external",
        "availability": "unavailable",
        "observedAt": None,
        "ttl": "not-observed",
        "provides": [
            "ENR.NET.REPUTATION", "ENR.PKG.REPUTATION",
            "ENR.ARTF.REPUTATION",
        ],
        "unavailableReason": "offline engine: indicator and package reputation feeds are intentionally not bundled",
    },
    {
        "id": "release-temporal-history",
        "name": "Release and maintainer temporal history",
        "kind": "external",
        "availability": "unavailable",
        "observedAt": None,
        "ttl": "not-observed",
        "provides": [
            "ENR.TIME.DORMANCY", "ENR.TIME.COORDINATED",
            "ENR.TIME.PRESTAGED",
        ],
        "unavailableReason": "offline engine: publication timelines and maintainer history require registry/VCS providers",
    },
    {
        "id": "build-reproducibility",
        "name": "Build reproducibility and source-to-binary drift",
        "kind": "external",
        "availability": "unavailable",
        "observedAt": None,
        "ttl": "not-observed",
        "provides": [
            "ENR.DRIFT.REPRO", "ENR.DRIFT.BEHAVIOR",
        ],
        "unavailableReason": "offline engine: rebuilds, attestations, and binary behavior comparison are not bundled",
    },
]


def _observed_at(report: dict | None) -> str | None:
    scan = (report or {}).get("scan") or {}
    return scan.get("completedAt") or scan.get("startedAt") or None


def _provider_ref() -> dict:
    return {
        "id": _LOCAL_PROVIDER_ID,
        "name": _LOCAL_PROVIDER_NAME,
        "kind": "local",
        "availability": "active",
    }


_WEIGHTING_RULE = ("If the fact applies to a finding's cited atom families, adjust "
                   "confidence by step; never change severity or the finding set.")


def _weight_cell(effect: str) -> dict:
    step = _AMPLIFY_STEP if effect in ("amplifying", "attenuating") else 0.0
    if effect == "attenuating":
        step = -step
    return {"effect": effect, "step": step, "ceiling": _CONF_CEILING, "rule": _WEIGHTING_RULE}


def _weighting(effect: str, composition_map=None) -> dict:
    """The per-lens weighting model. Lens-neutral by default (a single `default`
    cell keyed by atom families); when a product passes a composition_map it is
    reported under that product's lens key (mcd here) so the product view can show
    the same +/- step and ceiling next to the compositions it touches."""
    cell = _weight_cell(effect)
    return {"mcd": cell} if composition_map is not None else {"default": cell}


def _enr(eid, fact, source, effect, applies_to, rationale, report: dict | None = None,
         composition_map=None):
    """Build one enrichment fact. Lens-neutral (families only) by default. If a
    product passes a composition_map (fact id -> composition ids), the fact also
    carries that product's lens tag and the compositions the fact applies to; the
    confidence math (in `apply`) always keys off `appliesTo` atom families, so the
    mapping is presentational and never alters recall or the confidence result."""
    out = {
        "id": eid,
        "fact": fact,
        "source": source,
        "effect": effect,
        "appliesTo": list(applies_to),
        "rationale": rationale,
        "provider": _provider_ref(),
        "observedAt": _observed_at(report),
        "ttl": _LOCAL_TTL,
        "weighting": _weighting(effect, composition_map),
    }
    if composition_map is not None:
        out["appliesToLenses"] = ["mcd"]
        out["appliesToCompositions"] = list(composition_map.get(eid, []))
    return out


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _read_json(path: Path):
    try:
        return json.loads(_read_text(path))
    except Exception:
        return None


def _read_toml(path: Path):
    if tomllib is None:
        return None
    try:
        return tomllib.loads(_read_text(path))
    except Exception:
        return None


def _target_root(report: dict) -> Path | None:
    p = ((report.get("target") or {}).get("path") or "").strip()
    if not p:
        return None
    root = Path(p)
    try:
        root = root.resolve()
    except Exception:
        pass
    return root if root.is_dir() else None


def _walk_dependency_files(root: Path) -> tuple[list[Path], list[Path]]:
    manifests, locks = [], []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS
                       and (not d.startswith(".") or d == ".github")]
        for name in filenames:
            p = Path(dirpath) / name
            if name in _MANIFEST_NAMES:
                manifests.append(p)
            elif name in _LOCKFILE_NAMES:
                locks.append(p)
    return manifests, locks


def _rel(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except Exception:
        return path.name


def _norm_name(name: str, ecosystem: str) -> str:
    n = (name or "").strip().lower()
    if ecosystem in ("npm", "pypi", "cargo", "rubygems"):
        n = n.replace("_", "-")
    return n


def _dep(name, spec, ecosystem, manifest, kind="runtime"):
    return {
        "name": _norm_name(str(name), ecosystem),
        "display": str(name),
        "specifier": "" if spec is None else str(spec).strip(),
        "ecosystem": ecosystem,
        "manifest": manifest,
        "kind": kind,
    }


def _lock(name, version, ecosystem, lockfile, source=""):
    return {
        "name": _norm_name(str(name), ecosystem),
        "display": str(name),
        "version": "" if version is None else str(version).strip(),
        "ecosystem": ecosystem,
        "lockfile": lockfile,
        "source": "" if source is None else str(source).strip(),
    }


def _host(url: str) -> str:
    m = re.match(r"(?i)^[a-z][a-z0-9+.-]*://([^/@]+@)?([^/:?#]+)", url or "")
    return (m.group(2).lower() if m else "")


def _source_hint(value: str) -> str:
    s = (value or "").strip()
    low = s.lower()
    if not s:
        return ""
    if low.startswith(("file:", "link:", "path:", "workspace:")) or low.startswith(("./", "../", "/")):
        return "local-path"
    if low.startswith(("git+", "git://", "ssh://")) or re.search(r"(?i)\bgit(hub|lab)?\.com[:/]", s):
        return "git"
    if low.startswith("http://"):
        return "plain-http-url"
    if low.startswith("https://"):
        host = _host(s)
        return "" if host in _DEFAULT_SOURCE_HOSTS else "direct-or-custom-url"
    if "registry=" in low or "--registry" in low or "index-url" in low:
        return "registry-override"
    return ""


def _is_unpinned(dep: dict, locked: bool) -> bool:
    if locked:
        return False
    spec = (dep.get("specifier") or "").strip()
    low = spec.lower()
    if not spec or low in ("*", "x", "latest"):
        return True
    if _source_hint(spec):
        return False
    eco = dep.get("ecosystem")
    if eco == "npm":
        return not bool(re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?", spec))
    if eco == "pypi":
        return "==" not in spec and "===" not in spec
    if eco == "cargo":
        return not spec.startswith("=")
    if eco in ("composer", "rubygems"):
        return not bool(re.fullmatch(r"=?\s*\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9.-]+)?", spec))
    return False


def _python_req_name(req: str) -> tuple[str | None, str]:
    s = req.strip()
    if not s or s.startswith("#") or s.startswith("-"):
        return None, ""
    if "#egg=" in s:
        name = s.rsplit("#egg=", 1)[1].split("&", 1)[0]
        return name, s
    if re.match(r"(?i)^(git\+|https?://)", s):
        return None, s
    m = re.match(r"\s*([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(.*)$", s)
    return (m.group(1), m.group(2).strip()) if m else (None, s)


def _parse_package_json(path: Path, root: Path) -> list[dict]:
    data = _read_json(path)
    if not isinstance(data, dict):
        return []
    out = []
    rel = _rel(root, path)
    for section in ("dependencies", "optionalDependencies", "peerDependencies", "devDependencies"):
        deps = data.get(section)
        if isinstance(deps, dict):
            kind = "dev" if section == "devDependencies" else "runtime"
            out += [_dep(k, v, "npm", rel, kind) for k, v in deps.items()]
    return out


def _parse_package_lock(path: Path, root: Path) -> list[dict]:
    data = _read_json(path)
    if not isinstance(data, dict):
        return []
    rel = _rel(root, path)
    out = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, meta in packages.items():
            if not key or "node_modules/" not in key or not isinstance(meta, dict):
                continue
            name = key.rsplit("node_modules/", 1)[1]
            out.append(_lock(name, meta.get("version"), "npm", rel, meta.get("resolved", "")))
    deps = data.get("dependencies")
    if isinstance(deps, dict):
        for name, meta in deps.items():
            if isinstance(meta, dict):
                out.append(_lock(name, meta.get("version"), "npm", rel, meta.get("resolved", "")))
    return out


def _parse_yarn_lock(path: Path, root: Path) -> list[dict]:
    rel = _rel(root, path)
    out, names, version, resolved = [], [], "", ""

    def flush():
        for name in names:
            out.append(_lock(name, version, "npm", rel, resolved))

    for line in _read_text(path).splitlines():
        if line and not line.startswith((" ", "#")) and line.rstrip().endswith(":"):
            flush()
            raw = line.rstrip()[:-1]
            names, version, resolved = [], "", ""
            for item in raw.split(","):
                item = item.strip().strip('"').strip("'")
                base = item.rsplit("@", 1)[0] if item.startswith("@") else item.split("@", 1)[0]
                if base:
                    names.append(base)
        else:
            m = re.match(r"\s+version\s+[\"']?([^\"']+)", line)
            if m:
                version = m.group(1).strip()
            m = re.match(r"\s+resolved\s+[\"']?([^\"']+)", line)
            if m:
                resolved = m.group(1).strip()
    flush()
    return out


def _parse_pnpm_lock(path: Path, root: Path) -> list[dict]:
    rel = _rel(root, path)
    out = []
    for line in _read_text(path).splitlines():
        m = re.match(r"\s{2,}/?(@?[^:\s]+?)@([^:\s(/]+)(?:\([^)]*\))?:\s*$", line)
        if m:
            out.append(_lock(m.group(1), m.group(2), "npm", rel))
    return out


def _parse_requirements(path: Path, root: Path) -> list[dict]:
    rel = _rel(root, path)
    out = []
    for line in _read_text(path).splitlines():
        name, spec = _python_req_name(line)
        if name:
            out.append(_dep(name, spec, "pypi", rel))
    return out


def _parse_pyproject(path: Path, root: Path) -> list[dict]:
    data = _read_toml(path)
    if not isinstance(data, dict):
        return []
    rel = _rel(root, path)
    out = []
    project = data.get("project") or {}
    for req in project.get("dependencies") or []:
        name, spec = _python_req_name(str(req))
        if name:
            out.append(_dep(name, spec, "pypi", rel))
    optional = project.get("optional-dependencies") or {}
    if isinstance(optional, dict):
        for reqs in optional.values():
            for req in reqs if isinstance(reqs, list) else []:
                name, spec = _python_req_name(str(req))
                if name:
                    out.append(_dep(name, spec, "pypi", rel, "optional"))
    poetry = (((data.get("tool") or {}).get("poetry") or {}).get("dependencies") or {})
    if isinstance(poetry, dict):
        for name, spec in poetry.items():
            if str(name).lower() != "python":
                out.append(_dep(name, spec if isinstance(spec, str) else spec.get("version", ""),
                                "pypi", rel))
    return out


def _parse_python_lock(path: Path, root: Path) -> list[dict]:
    rel = _rel(root, path)
    if path.name == "Pipfile.lock":
        data = _read_json(path)
        out = []
        if isinstance(data, dict):
            for section in ("default", "develop"):
                deps = data.get(section) or {}
                for name, meta in deps.items():
                    if isinstance(meta, dict):
                        out.append(_lock(name, meta.get("version", ""), "pypi", rel,
                                         meta.get("file") or meta.get("path") or meta.get("git", "")))
        return out
    data = _read_toml(path)
    out = []
    if isinstance(data, dict):
        for pkg in data.get("package") or []:
            if isinstance(pkg, dict) and pkg.get("name"):
                src = pkg.get("source") or {}
                out.append(_lock(pkg["name"], pkg.get("version", ""), "pypi", rel,
                                 src.get("url") if isinstance(src, dict) else ""))
    return out


def _parse_cargo_toml(path: Path, root: Path) -> list[dict]:
    data = _read_toml(path)
    if not isinstance(data, dict):
        return []
    rel = _rel(root, path)
    out = []
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        deps = data.get(section) or {}
        if isinstance(deps, dict):
            for name, spec in deps.items():
                if isinstance(spec, dict):
                    spec_s = spec.get("version") or spec.get("git") or spec.get("path") or ""
                else:
                    spec_s = spec
                out.append(_dep(name, spec_s, "cargo", rel,
                                "dev" if section == "dev-dependencies" else "runtime"))
    return out


def _parse_cargo_lock(path: Path, root: Path) -> list[dict]:
    data = _read_toml(path)
    rel = _rel(root, path)
    out = []
    if isinstance(data, dict):
        for pkg in data.get("package") or []:
            if isinstance(pkg, dict) and pkg.get("name"):
                out.append(_lock(pkg["name"], pkg.get("version", ""), "cargo", rel, pkg.get("source", "")))
    return out


def _parse_go_mod(path: Path, root: Path) -> list[dict]:
    rel = _rel(root, path)
    out = []
    in_require = False
    for raw in _read_text(path).splitlines():
        line = raw.split("//", 1)[0].strip()
        if line == "require (":
            in_require = True
            continue
        if in_require and line == ")":
            in_require = False
            continue
        if line.startswith("require "):
            parts = line.split()
            if len(parts) >= 3:
                out.append(_dep(parts[1], parts[2], "go", rel))
        elif in_require and line:
            parts = line.split()
            if len(parts) >= 2:
                out.append(_dep(parts[0], parts[1], "go", rel))
        elif line.startswith("replace ") and "=>" in line:
            left, right = line[len("replace "):].split("=>", 1)
            name = left.split()[0]
            out.append(_dep(name, right.strip(), "go", rel, "replace"))
    return out


def _parse_go_sum(path: Path, root: Path) -> list[dict]:
    rel = _rel(root, path)
    out, seen = [], set()
    for line in _read_text(path).splitlines():
        parts = line.split()
        if len(parts) >= 2:
            name, version = parts[0], parts[1].replace("/go.mod", "")
            key = (name, version)
            if key not in seen:
                seen.add(key)
                out.append(_lock(name, version, "go", rel))
    return out


def _parse_composer_json(path: Path, root: Path) -> list[dict]:
    data = _read_json(path)
    rel = _rel(root, path)
    out = []
    if isinstance(data, dict):
        for section in ("require", "require-dev"):
            deps = data.get(section) or {}
            if isinstance(deps, dict):
                for name, spec in deps.items():
                    if not str(name).startswith(("php", "ext-")):
                        out.append(_dep(name, spec, "composer", rel,
                                        "dev" if section == "require-dev" else "runtime"))
    return out


def _parse_composer_lock(path: Path, root: Path) -> list[dict]:
    data = _read_json(path)
    rel = _rel(root, path)
    out = []
    if isinstance(data, dict):
        for section in ("packages", "packages-dev"):
            for pkg in data.get(section) or []:
                if isinstance(pkg, dict) and pkg.get("name"):
                    out.append(_lock(pkg["name"], pkg.get("version", ""), "composer", rel,
                                     (pkg.get("source") or {}).get("url", "")))
    return out


def _parse_gemfile(path: Path, root: Path) -> list[dict]:
    rel = _rel(root, path)
    out = []
    for m in re.finditer(r"""(?m)^\s*gem\s+['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]+)['"])?""",
                         _read_text(path)):
        out.append(_dep(m.group(1), m.group(2) or "", "rubygems", rel))
    return out


def _parse_gem_lock(path: Path, root: Path) -> list[dict]:
    rel = _rel(root, path)
    out = []
    for m in re.finditer(r"(?m)^\s{4}([A-Za-z0-9_.-]+)\s+\(([^)]+)\)", _read_text(path)):
        out.append(_lock(m.group(1), m.group(2), "rubygems", rel))
    return out


def _dependency_context(root: Path) -> dict:
    manifests, locks = _walk_dependency_files(root)
    deps, locked = [], []
    for p in manifests:
        if p.name == "package.json":
            deps += _parse_package_json(p, root)
        elif p.name == "requirements.txt":
            deps += _parse_requirements(p, root)
        elif p.name == "pyproject.toml":
            deps += _parse_pyproject(p, root)
        elif p.name == "Cargo.toml":
            deps += _parse_cargo_toml(p, root)
        elif p.name == "go.mod":
            deps += _parse_go_mod(p, root)
        elif p.name == "composer.json":
            deps += _parse_composer_json(p, root)
        elif p.name == "Gemfile":
            deps += _parse_gemfile(p, root)
    for p in locks:
        if p.name in ("package-lock.json", "npm-shrinkwrap.json"):
            locked += _parse_package_lock(p, root)
        elif p.name == "yarn.lock":
            locked += _parse_yarn_lock(p, root)
        elif p.name == "pnpm-lock.yaml":
            locked += _parse_pnpm_lock(p, root)
        elif p.name in ("poetry.lock", "uv.lock", "Pipfile.lock"):
            locked += _parse_python_lock(p, root)
        elif p.name == "Cargo.lock":
            locked += _parse_cargo_lock(p, root)
        elif p.name == "go.sum":
            locked += _parse_go_sum(p, root)
        elif p.name == "composer.lock":
            locked += _parse_composer_lock(p, root)
        elif p.name == "Gemfile.lock":
            locked += _parse_gem_lock(p, root)
    return {"manifests": manifests, "lockfiles": locks, "deps": deps, "locked": locked}


def _label_dep(dep: dict) -> str:
    spec = dep.get("specifier") or "unknown"
    return f"{dep.get('display')}@{spec} ({dep.get('manifest')})"


def _label_lock(lock: dict) -> str:
    ver = lock.get("version") or "unknown"
    src = lock.get("source")
    extra = f", {src[:60]}" if src else ""
    return f"{lock.get('display')}@{ver} ({lock.get('lockfile')}{extra})"


def _examples(items, label_fn) -> str:
    labels = [label_fn(i) for i in items[:_MAX_DEP_EXAMPLES]]
    extra = len(items) - len(labels)
    text = "; ".join(labels)
    return text + (f"; +{extra} more" if extra > 0 else "")


def _dependency_enrichment(report: dict, composition_map=None) -> list:
    root = _target_root(report)
    if root is None:
        return []
    ctx = _dependency_context(root)
    deps, locked = ctx["deps"], ctx["locked"]
    if not deps and not locked:
        return []

    lock_names_by_eco = {}
    for item in locked:
        lock_names_by_eco.setdefault(item["ecosystem"], set()).add(item["name"])
    deps_by_eco = {}
    for dep in deps:
        deps_by_eco.setdefault(dep["ecosystem"], []).append(dep)

    missing, no_lock, fully_locked = [], [], []
    for eco, eco_deps in deps_by_eco.items():
        lock_names = lock_names_by_eco.get(eco, set())
        if not lock_names:
            no_lock.extend(eco_deps)
            continue
        eco_missing = [d for d in eco_deps if d["name"] not in lock_names]
        if eco_missing:
            missing.extend(eco_missing)
        else:
            fully_locked.extend(eco_deps)

    source_deps = [d for d in deps if _source_hint(d.get("specifier", ""))]
    source_locks = [l for l in locked if _source_hint(l.get("source", ""))]
    unpinned = []
    for dep in deps:
        locked_dep = dep["name"] in lock_names_by_eco.get(dep["ecosystem"], set())
        if _is_unpinned(dep, locked_dep):
            unpinned.append(dep)
    unknown_deps = [d for d in deps if not d.get("specifier") or d.get("specifier", "").lower() == "latest"]
    unknown_locks = [l for l in locked if not l.get("version")]

    out = []
    if no_lock:
        out.append(_enr(
            "ENR.DEP.NO_LOCKFILE",
            "declared dependencies have no local lockfile coverage: " + _examples(no_lock, _label_dep),
            "local dependency manifests/lockfiles (static)", "amplifying",
            ("PKGM", "EXEC", "LOAD", "NETW"),
            "without a lockfile, dependency resolution can drift between review and install",
            report, composition_map))
    if missing:
        out.append(_enr(
            "ENR.DEP.UNLOCKED",
            "declared dependencies are absent from the local lockfile: " + _examples(missing, _label_dep),
            "declared-vs-locked comparison (static)", "amplifying",
            ("PKGM", "EXEC", "LOAD", "NETW"),
            "a declared-but-unlocked dependency may be new, stale, or resolved outside the reviewed lockfile",
            report, composition_map))
    if fully_locked and not missing and not no_lock:
        out.append(_enr(
            "ENR.DEP.LOCKED",
            f"{len(fully_locked)} declared dependenc(ies) have matching local lockfile entries",
            "declared-vs-locked comparison (static)", "neutral",
            ("PKGM",),
            "local lock coverage is useful context, but it does not prove package identity or benign behavior",
            report, composition_map))
    if source_deps or source_locks:
        bits = []
        if source_deps:
            bits.append(_examples(source_deps, _label_dep))
        if source_locks:
            bits.append(_examples(source_locks, _label_lock))
        out.append(_enr(
            "ENR.DEP.SOURCE",
            "dependencies use local path, git, direct URL, or non-default source hints: " + " | ".join(bits),
            "local manifest/lockfile source fields (static)", "amplifying",
            ("PKGM", "EXEC", "LOAD", "NETW"),
            "non-registry or custom-source dependencies bypass some normal registry review and provenance cues",
            report, composition_map))
    if unpinned:
        out.append(_enr(
            "ENR.PKG.UNPINNED",
            "dependency versions are unpinned or range-only without matching lock coverage: "
            + _examples(unpinned, _label_dep),
            "local dependency manifests (static)", "amplifying",
            ("PKGM", "EXEC", "LOAD", "NETW"),
            "unpinned versions increase install-time drift and make source-to-installed-code comparison weaker",
            report, composition_map))
    if unknown_deps or unknown_locks:
        bits = []
        if unknown_deps:
            bits.append(_examples(unknown_deps, _label_dep))
        if unknown_locks:
            bits.append(_examples(unknown_locks, _label_lock))
        out.append(_enr(
            "ENR.PKG.UNKNOWN_VERSION",
            "dependency version metadata is missing or non-concrete: " + " | ".join(bits),
            "local package metadata (static)", "neutral",
            ("PKGM",),
            "unknown local version metadata is context for review; registry age and ownership still need OSINT",
            report, composition_map))
    return out


def fact_catalog(composition_map=None) -> list[dict]:
    """Machine-readable summary of the local enrichment facts and their weighting.

    Lens-neutral by default (each fact's id and its +/- weighting). A product may
    pass its composition_map (fact id -> composition ids) to also list the
    compositions each fact applies to under that product's lens."""
    fact_ids = sorted(composition_map) if composition_map is not None else list(_LOCAL_FACT_IDS)
    out = []
    for eid in fact_ids:
        effect = "neutral" if eid in ("ENR.DEP.LOCKED", "ENR.PKG.UNKNOWN_VERSION") else "amplifying"
        entry = {"id": eid, "weighting": _weighting(effect, composition_map)}
        if composition_map is not None:
            entry["appliesToLenses"] = ["mcd"]
            entry["appliesToCompositions"] = list(composition_map.get(eid, []))
        out.append(entry)
    return out


def provider_status(report: dict | None = None) -> list[dict]:
    """Provider availability and freshness, without probing network state."""
    root = _target_root(report or {})
    observed_at = _observed_at(report)
    manifest_count = lockfile_count = 0
    if root is not None:
        manifests, lockfiles = _walk_dependency_files(root)
        manifest_count, lockfile_count = len(manifests), len(lockfiles)

    local = {
        "id": _LOCAL_PROVIDER_ID,
        "name": _LOCAL_PROVIDER_NAME,
        "kind": "local",
        "availability": "active",
        "observedAt": observed_at,
        "ttl": _LOCAL_TTL,
        "provides": ["ENR.EXEC.PHASE", "ENR.DEP.RESOLUTION", "ENR.DRIFT.NATIVE"],
        "unavailableReason": None,
    }
    deps = {
        "id": "local-dependency-context",
        "name": "Local dependency manifests and lockfiles",
        "kind": "local",
        "availability": "active" if root is not None else "unavailable",
        "observedAt": observed_at if root is not None else None,
        "ttl": _LOCAL_TTL if root is not None else "not-observed",
        "provides": [
            "ENR.DEP.NO_LOCKFILE", "ENR.DEP.UNLOCKED", "ENR.DEP.LOCKED",
            "ENR.DEP.SOURCE", "ENR.PKG.UNPINNED", "ENR.PKG.UNKNOWN_VERSION",
        ],
        "manifestCount": manifest_count,
        "lockfileCount": lockfile_count,
        "unavailableReason": None if root is not None else "target path is absent or is not a local directory",
    }
    return [local, deps] + [dict(s) for s in _UNAVAILABLE_PROVIDER_STATUS]


def provider_notes(report: dict | None = None) -> list[str]:
    statuses = provider_status(report)
    local = next((s for s in statuses if s["id"] == _LOCAL_PROVIDER_ID), {})
    observed = local.get("observedAt") or "scan timestamp unavailable"
    unavailable = [s["id"] for s in statuses if s.get("availability") == "unavailable"
                   and s.get("kind") == "external"]
    notes = [
        "Enrichment providers: local static provider active "
        f"(observedAt={observed}; ttl={local.get('ttl', _LOCAL_TTL)}); unavailable offline "
        "providers: " + ", ".join(unavailable) + "."
    ]
    deps = next((s for s in statuses if s["id"] == "local-dependency-context"), {})
    if deps.get("availability") == "active" and (deps.get("manifestCount") or deps.get("lockfileCount")):
        notes.append(
            f"Offline dependency context: inspected {deps.get('manifestCount', 0)} dependency "
            f"manifest(s) and {deps.get('lockfileCount', 0)} lockfile(s) for declared-vs-locked, "
            "unpinned-version, and source-hint enrichment.")
    return notes


class EnrichmentProvider(Protocol):
    """A source of enrichment. The local provider below is deterministic and
    offline. Networked providers (registry, WHOIS, threat intel) implement the
    same shape for an online deployment and are intentionally not bundled here."""

    def provide(self, report: dict) -> list:  # returns a list of enrichment dicts
        ...


class LocalProvider:
    """Deterministic enrichment derived from observations already in the report.
    No network, no clock, no external services."""

    def __init__(self, composition_map=None):
        self.composition_map = composition_map

    def provide(self, report: dict) -> list:
        composition_map = self.composition_map
        obs = report.get("observations", [])
        atoms = {o.get("atom") for o in obs}
        out = []
        if "PKGM.INSTALL" in atoms:
            out.append(_enr(
                "ENR.EXEC.PHASE",
                "code runs at install time via a package lifecycle hook, before any explicit use",
                "manifest install hooks (static)", "amplifying",
                ("EXEC", "LOAD", "NETW", "FSYS", "CRED"),
                "install-time execution runs before a consumer can review or sandbox it, so a "
                "malicious-code finding that executes at install carries more weight",
                report, composition_map))
        if "PKGM.UNDECLARED" in atoms:
            out.append(_enr(
                "ENR.DEP.RESOLUTION",
                "imports a module that is not a declared dependency (unpinned resolution path)",
                "manifest vs imports (static)", "amplifying",
                ("NETW", "EXEC", "LOAD"),
                "an unpinned import can be supplied by whoever registers the name, so adverse "
                "behavior near it is more concerning",
                report, composition_map))
        if any((o.get("atom") or "").startswith("BIN.") or o.get("method") == "binary-imports" for o in obs):
            out.append(_enr(
                "ENR.DRIFT.NATIVE",
                "ships native or packed binary components not derivable from the source tree",
                "binary triage (static)", "amplifying",
                ("EXEC", "LOAD"),
                "opaque native code cannot be read at the source level, so source-level review "
                "is incomplete and execution findings carry more weight",
                report, composition_map))
        out.extend(_dependency_enrichment(report, composition_map))
        return out


def derive(report: dict, providers=None, composition_map=None) -> list:
    """Collect enrichment from the providers (local only by default).

    `composition_map` is optional product context (fact id -> composition ids). The
    engine emits lens-neutral facts (keyed by atom family) when it is None; a
    product passes its own map so its facts also name the compositions they touch.
    The confidence math never reads compositions, so this only enriches metadata."""
    providers = providers if providers is not None else [LocalProvider(composition_map)]
    out = []
    for p in providers:
        try:
            out.extend(p.provide(report))
        except Exception:
            continue
    return out


def _finding_families(finding, obs_by_id) -> set:
    """Atom families (NETW, EXEC, ...) of the observations a finding cites."""
    fams = set()
    for oid in finding.get("evidence", []):
        atom = (obs_by_id.get(oid) or {}).get("atom") or ""
        if atom:
            fams.add(atom.split(".")[0])
    return fams


def _applies(families, enr) -> bool:
    return bool(families & set(enr.get("appliesTo", [])))


def apply(findings: list, enrichment: list, obs_by_id: dict) -> list:
    """Return findings annotated with an effective confidence: base confidence
    adjusted by the amplifying/attenuating enrichment that applies to each, bounded.
    Applicability is by the atom families a finding cites. Does not add or drop
    findings."""
    if not enrichment:
        return findings
    out = []
    for f in findings:
        base = f.get("confidence")
        if not isinstance(base, (int, float)):
            out.append(f)
            continue
        fams = _finding_families(f, obs_by_id)
        applied = [e for e in enrichment if _applies(fams, e)]
        delta = 0.0
        for e in applied:
            if e["effect"] == "amplifying":
                delta += _AMPLIFY_STEP
            elif e["effect"] == "attenuating":
                delta -= _AMPLIFY_STEP
        eff = max(0.0, min(_CONF_CEILING, round(base + delta, 2)))
        g = dict(f)
        g["effectiveConfidence"] = eff
        if applied:
            g["enrichment"] = [{"id": e["id"], "effect": e["effect"], "rationale": e["rationale"]}
                               for e in applied]
        out.append(g)
    return out

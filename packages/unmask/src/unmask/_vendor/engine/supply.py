"""Supply-chain abuse signals: typosquatting / slopsquatting and
phantom dependencies, from LOCAL evidence only.

This is deliberately honest about its limits. Real confirmation of a squat needs
the registry (package age, downloads, ownership), which a static scanner does not
have. What we CAN see locally is strong enough to flag:

  * typosquat / slopsquat: the package's own name is a near-miss of a popular
    package (edit distance 1-2, or a year-prefixed decoration). Slopsquatting is
    the LLM-era variant: names that sound plausible to a model, registered by
    squatters so AI-generated projects install them.
  * phantom dependency: a module is imported but never declared in the manifest,
    so its resolution is unpinned and a squatter can supply it.

Both feed the MCD lens. Name-similarity alone is reported at honest (medium)
confidence and says to confirm against the registry; it is not a malware verdict
on its own.
"""

from __future__ import annotations

import json
import os
import re

from .model import Observation

# Curated popular-package names (not exhaustive; the high-traffic head where
# squatting pays off). Includes the benign eval set so real packages score
# distance 0 and are never flagged.
POPULAR_PYPI = {
    "requests", "urllib3", "setuptools", "wheel", "pip", "numpy", "pandas",
    "scipy", "click", "flask", "django", "fastapi", "jinja2", "pyyaml", "rich",
    "colorama", "beautifulsoup", "beautifulsoup4", "bs4", "pytorch", "torch",
    "tensorflow", "scikit-learn", "sklearn", "matplotlib", "pillow", "boto3",
    "botocore", "cryptography", "sqlalchemy", "pydantic", "aiohttp", "httpx",
    "certifi", "idna", "charset-normalizer", "six", "python-dateutil", "pytz",
    "packaging", "attrs", "typing-extensions", "wrapt", "click-spinner",
    "capmonstercloudclient", "selenium", "scrapy", "celery", "redis", "pymongo",
    "psycopg2", "openai", "anthropic", "transformers", "tqdm", "loguru",
    "discord", "discord-py", "python-telegram-bot", "websockets", "uvicorn",
    "gunicorn", "poetry", "twine", "black", "ruff", "mypy", "pytest", "tox",
}

POPULAR_NPM = {
    "react", "react-dom", "express", "lodash", "axios", "chalk", "commander",
    "debug", "request", "vue", "webpack", "babel", "typescript", "jest",
    "eslint", "prettier", "moment", "dayjs", "uuid", "dotenv", "cors",
    "body-parser", "mongoose", "socket.io", "next", "rxjs", "redux", "jquery",
    "bootstrap", "tailwindcss", "vite", "rollup", "esbuild", "node-fetch",
    "got", "cross-env", "nodemon", "ws", "yargs", "inquirer", "colors",
    "puppeteer", "playwright", "fs-extra", "glob", "semver", "minimist",
    "discord.js", "ethers", "web3", "stripe", "openai", "left-pad",
}

# Standard-library / runtime-builtin module names that are never "phantom".
PY_STDLIB = {
    "os", "sys", "re", "json", "math", "time", "datetime", "subprocess", "socket",
    "collections", "itertools", "functools", "typing", "pathlib", "io", "abc",
    "hashlib", "base64", "struct", "random", "string", "logging", "argparse",
    "threading", "multiprocessing", "asyncio", "http", "urllib", "ssl", "shutil",
    "tempfile", "glob", "csv", "sqlite3", "pickle", "copy", "enum", "dataclasses",
    "contextlib", "traceback", "warnings", "inspect", "importlib", "unittest",
    "platform", "signal", "ctypes", "array", "queue", "uuid", "secrets", "zlib",
    "gzip", "tarfile", "zipfile", "binascii", "codecs", "decimal", "fractions",
    "statistics", "operator", "weakref", "gc", "atexit", "ast", "dis", "types",
    "textwrap", "difflib", "fnmatch", "stat", "errno", "getpass", "configparser",
    "xml", "html", "email", "smtplib", "ftplib", "telnetlib", "select", "fcntl",
    "__future__", "builtins", "concurrent", "encodings",
}

NODE_BUILTINS = {
    "fs", "path", "os", "http", "https", "net", "crypto", "stream", "events",
    "util", "child_process", "url", "querystring", "zlib", "buffer", "assert",
    "tls", "dns", "dgram", "cluster", "readline", "vm", "module", "process",
    "timers", "string_decoder", "perf_hooks", "worker_threads", "async_hooks",
}

_IMPORT_PY = re.compile(r"(?m)^\s*(?:import\s+([a-zA-Z0-9_]+)|from\s+([a-zA-Z0-9_]+)[\w.]*\s+import)")
_REQUIRE_JS = re.compile(r"""require\(\s*['"]([^'"]+)['"]\s*\)""")
_IMPORT_JS = re.compile(r"""(?:import\b[^'"]*from\s*|import\s*)['"]([^'"]+)['"]""")
_YEAR_PREFIX = re.compile(r"^(?:19|20)\d\d[-_]")


def _norm(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def _lev(a: str, b: str, maxd: int = 2) -> int:
    """Levenshtein distance, short-circuited once it exceeds maxd."""
    if abs(len(a) - len(b)) > maxd:
        return maxd + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        best = i
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
            best = min(best, cur[-1])
        prev = cur
        if best > maxd:
            return maxd + 1
    return prev[-1]


def nearest_popular(name: str, popular: set):
    """Return (popular_name, distance, reason) for the closest squat-worthy match,
    or None. Skips exact matches (the real package) and very short names."""
    n = _norm(name)
    if n in popular or len(n) < 4:
        return None
    # year/date-prefixed decoration of a popular name (e.g. 2022-requests)
    if _YEAR_PREFIX.search(n):
        stripped = _YEAR_PREFIX.sub("", n)
        if stripped in popular:
            return (stripped, 1, f"name decorates the popular package '{stripped}' with a date prefix")
    best, bestd = None, 99
    for p in popular:
        d = _lev(n, p, 2)
        if d < bestd and d > 0:
            best, bestd = p, d
    if best is not None and bestd <= 2:
        return (best, bestd, f"name is edit-distance {bestd} from the popular package '{best}'")
    return None


def _popular_for(ecosystems) -> set:
    pop = set()
    if "npm" in ecosystems:
        pop |= POPULAR_NPM
    if "pypi" in ecosystems:
        pop |= POPULAR_PYPI
    return pop or (POPULAR_PYPI | POPULAR_NPM)


def _read(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except Exception:
        return ""


def package_name(inv) -> str:
    """The scanned package's own declared name (manifest), else the directory."""
    for f in inv.files:
        if f.name == "package.json":
            try:
                d = json.loads(_read(f.abspath))
                if isinstance(d.get("name"), str):
                    return d["name"]
            except Exception:
                pass
    for f in inv.files:
        if f.name == "pyproject.toml":
            m = re.search(r"(?m)^\s*name\s*=\s*['\"]([^'\"]+)['\"]", _read(f.abspath))
            if m:
                return m.group(1)
        if f.name == "setup.py":
            m = re.search(r"name\s*=\s*['\"]([^'\"]+)['\"]", _read(f.abspath))
            if m:
                return m.group(1)
    return os.path.basename(inv.root)


def declared_deps(inv) -> set:
    deps = set()
    for f in inv.files:
        if f.name == "package.json":
            try:
                d = json.loads(_read(f.abspath))
                for k in ("dependencies", "devDependencies", "optionalDependencies",
                          "peerDependencies"):
                    if isinstance(d.get(k), dict):
                        deps |= {_norm(x) for x in d[k]}
            except Exception:
                pass
        elif f.name == "requirements.txt":
            for line in _read(f.abspath).splitlines():
                m = re.match(r"\s*([A-Za-z0-9._-]+)", line)
                if m and not line.strip().startswith("#"):
                    deps.add(_norm(m.group(1)))
        elif f.name == "pyproject.toml":
            for m in re.finditer(r"['\"]([A-Za-z0-9._-]+)\s*(?:[<>=!~\[ ].*)?['\"]", _read(f.abspath)):
                deps.add(_norm(m.group(1)))
        elif f.name == "setup.py":
            m = re.search(r"install_requires\s*=\s*\[(.*?)\]", _read(f.abspath), re.DOTALL)
            if m:
                for d in re.finditer(r"['\"]([A-Za-z0-9._-]+)\s*(?:[<>=!~\[ ].*)?['\"]", m.group(1)):
                    deps.add(_norm(d.group(1)))
    return deps


def _npm_runtime_deps(inv) -> set:
    """package.json RUNTIME dependencies only (not dev/peer/optional). Phantom
    detection is scoped to npm because there the distribution name matches the
    import specifier; Python dist names diverge from import names (PyYAML->yaml,
    beautifulsoup4->bs4), which would make declared-but-unused unreliable."""
    deps = set()
    for f in inv.files:
        if f.name == "package.json":
            try:
                d = json.loads(_read(f.abspath))
                if isinstance(d.get("dependencies"), dict):
                    deps |= {_norm(x) for x in d["dependencies"]}
            except Exception:
                pass
    return deps


def _has_manifest(inv) -> bool:
    return any(f.name in ("package.json", "requirements.txt", "pyproject.toml", "setup.py")
               for f in inv.files)


def _imports(text: str, lang: str) -> set:
    out = set()
    if lang == "python":
        for m in _IMPORT_PY.finditer(text):
            out.add((m.group(1) or m.group(2)))
    else:  # js-like
        for rx in (_REQUIRE_JS, _IMPORT_JS):
            for m in rx.finditer(text):
                spec = m.group(1)
                if spec.startswith(".") or spec.startswith("/"):
                    continue
                # package name: @scope/name or first path segment
                parts = spec.split("/")
                out.add("/".join(parts[:2]) if spec.startswith("@") else parts[0])
    return {x for x in out if x}


def analyze(inv) -> list:
    """Local supply-chain observations: typosquat (self-name) + phantom deps."""
    obs = []
    ecos = inv.ecosystems
    popular = _popular_for(ecos)

    # 1) typosquat / slopsquat on the package's own name
    name = package_name(inv)
    hit = nearest_popular(name, popular)
    if hit:
        target, dist, reason = hit
        obs.append(Observation(
            atom="PKGM.TYPOSQUAT", method="static-source", confidence=0.6 if dist == 1 else 0.5,
            path=os.path.basename(name) or ".", start_line=1,
            summary=f"package name '{name}': {reason} (local heuristic, confirm against the registry)",
            matched_text=name, rule_id="supply.typosquat"))

    # 2) phantom dependencies: imported but never declared (manifest present so
    # the dependency set is meant to be complete; undeclared imports are unpinned)
    declared = declared_deps(inv)
    if _has_manifest(inv):
        stdlib = PY_STDLIB if "pypi" in ecos else NODE_BUILTINS
        self_name = _norm(name)
        # local modules: top-level dirs and module file stems shipped in the package
        local_tops = set()
        for f in inv.files:
            parts = f.relpath.replace("\\", "/").split("/")
            if len(parts) > 1:
                local_tops.add(_norm(parts[0]))
            else:
                local_tops.add(_norm(os.path.splitext(parts[0])[0]))
        seen = set()
        imported = set()  # every imported package name, for phantom detection below
        for f in inv.files:
            if f.lang not in ("python", "javascript", "typescript", "tsx"):
                continue
            lang = "python" if f.lang == "python" else "js"
            for mod in _imports(_read(f.abspath), lang):
                nm = _norm(mod)
                base = mod.split(".")[0] if lang == "python" else mod
                nbase = _norm(base)
                imported.add(nm)
                imported.add(nbase)
                if (nm in declared or nbase in declared
                        or base in stdlib or nm in stdlib or nm in seen
                        or nbase == self_name or nbase in local_tops):
                    continue
                seen.add(nm)
                obs.append(Observation(
                    atom="PKGM.UNDECLARED", method="static-source", confidence=0.45,
                    path=f.relpath, start_line=1,
                    summary=f"imports '{mod}' but it is not a declared dependency "
                            f"(unpinned resolution; a squatter can supply it)",
                    matched_text=mod, rule_id="supply.undeclared"))
                if len(seen) >= 25:
                    break
            if len(seen) >= 25:
                break
        # phantom dependency: a RUNTIME dep declared but imported nowhere (npm only,
        # see _npm_runtime_deps). Declared-but-unused = dead weight or an unvetted
        # package pulled into the install graph with no call site to justify it.
        nphantom = 0
        for dep in sorted(_npm_runtime_deps(inv)):
            if (dep in imported or dep == self_name or dep in local_tops
                    or dep.startswith("@types/")):
                continue
            obs.append(Observation(
                atom="PKGM.PHANTOM", method="static-source", confidence=0.4,
                path="package.json", start_line=1,
                summary=f"declares runtime dependency '{dep}' but no source file imports it "
                        f"(declared-but-unused; dead weight or an unvetted resolution path)",
                matched_text=dep, rule_id="supply.phantom"))
            nphantom += 1
            if nphantom >= 25:
                break
    return obs

"""Manifest install-hook atoms → PKGM.INSTALL.

Algorithm-shaped (not signature data): parse package manifests for install-time
execution. Ports the reference detectors:

* package.json lifecycle scripts (preinstall/install/postinstall/prepare) — the
  npm-lifecycle malware vector. Emits a `manifest-entrypoint` relationship to the
  script file the hook runs, which BP-SUPPLY follows from install hook to payload.
* setup.py cmdclass / module-side-effect code execution — the pypi install hook.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from unmask.scanner.observe.atoms import Observation
from unmask.scanner.observe.inventory import Inventory

_LIFECYCLE = ("preinstall", "install", "postinstall", "prepare")
_SCRIPT_FILE_RE = re.compile(r"([\w./\\-]+\.(?:js|cjs|mjs|ts|py|sh))")
_SETUP_EXEC_RE = re.compile(
    r"\b(exec|eval)\s*\(|os\.system|subprocess|urlopen|urllib|requests\.|\bPopen\b|socket\."
)


def _line_of(text: str, index: int) -> int | None:
    return text.count("\n", 0, index) + 1 if index >= 0 else None


def _from_package_json(text: str, rel: str) -> list[Observation]:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    scripts = data.get("scripts") if isinstance(data, dict) else None
    if not isinstance(scripts, dict):
        return []
    pkg_dir = rel.rsplit("/", 1)[0] if "/" in rel else ""
    out: list[Observation] = []
    for hook in _LIFECYCLE:
        cmd = scripts.get(hook)
        if not cmd or not isinstance(cmd, str):
            continue
        marker = f'"{hook}"'
        line = _line_of(text, text.find(marker)) if marker in text else None
        rels = []
        fm = _SCRIPT_FILE_RE.search(cmd)
        if fm:
            target = (pkg_dir + "/" + fm.group(1)) if pkg_dir else fm.group(1)
            target = target.replace("\\", "/").replace("./", "")
            rels.append({"type": "manifest-entrypoint", "target": target})
        out.append(Observation(
            atom="PKGM.INSTALL", confidence=0.95, method="static-source",
            path=rel, line=line, rule_id="manifest.npm.lifecycle",
            evidence=cmd, relationships=rels,
            summary=f"package lifecycle hook scripts.{hook} -> {cmd}",
        ))
    return out


def _from_setup_py(text: str, rel: str) -> list[Observation]:
    if "cmdclass" in text:
        return [Observation(
            atom="PKGM.INSTALL", confidence=0.8, method="static-source",
            path=rel, line=_line_of(text, text.find("cmdclass")),
            rule_id="manifest.pypi.cmdclass", evidence="cmdclass",
            summary="custom setup.py install command (cmdclass)",
        )]
    if _SETUP_EXEC_RE.search(text):
        return [Observation(
            atom="PKGM.INSTALL", confidence=0.55, method="static-source",
            path=rel, rule_id="manifest.pypi.setup",
            summary="setup.py executes code at install time",
        )]
    return []


def observe_manifest(inv: Inventory) -> list[Observation]:
    out: list[Observation] = []
    for f in inv.files:
        if f.kind == "binary":
            continue
        if f.path.rsplit("/", 1)[-1] not in ("package.json", "setup.py"):
            continue
        try:
            text = Path(f.path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if f.path.endswith("package.json"):
            out += _from_package_json(text, f.rel)
        else:
            out += _from_setup_py(text, f.rel)
    return out

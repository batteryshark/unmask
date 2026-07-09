"""RE provider registration — the real skill-driven transform provider.

Replaces the capability stub. Loads ``skills-manifest.json`` (written by
``scripts/sync_skills.py``), reads each skill's ``skill.json`` for its capability
strings and prerequisites, and resolves prerequisites (``shutil.which`` + a version
check on each skill's ``prerequisites[].check`` argv). A skill present-but-prereq-
missing advertises NOTHING — so a binary that needs, say, jadx routes to an honest
blind spot instead of the old stub's misleading "decompile-jvm available".

Core never imports this module; it enumerates the ``unmask.providers`` entry-point
group and duck-types whatever it loads against :class:`TransformProvider`
(see ``unmask.transform.contract``). This provider implements ``transform``:
core hands it an :class:`ArtifactRef` + workdir, it shells out to the skill's
``entry.command`` with the artifact + workdir as positional args, parses the JSON
result the skill prints to stdout, and maps ``outputDir``/``outputFile`` →
:class:`DerivedSource` roots (or an ``atoms`` array → :class:`EmittedAtom` list for
the emit-atoms skills). Failures become :meth:`TransformResult.failed`.

No sandbox here yet (Tier-1 sandbox is a deferred milestone): the skill runs as a
local subprocess with a timeout, env scrubbed of ``*_SECRET*``/``*TOKEN*``/``*KEY*``,
writes confined to the workdir. The skill runtimes themselves are trusted code over
untrusted input (decompilers/extractors read bytes, they never execute the input).
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from unmask.transform.contract import (
    ArtifactRef, DerivedSource, EmittedAtom, TransformResult,
)

# The vendored skills ship alongside this package as data files.
_SKILLS_DIR = Path(__file__).resolve().parent.parent.parent / "skills"
_MANIFEST = _SKILLS_DIR / "skills-manifest.json"

# Skills whose result is a directory of recovered SOURCE to rescan (transform);
# everything else is an atom-emitter (triage/covert/secret scan → emit-atoms).
_SOURCE_RECOVERY_CAPS = {
    "unpack-archive", "extract-recursive",
    "deobfuscate-js", "deobfuscate", "unpack-js-bundle", "unminify-js",
    "decompile-jvm", "decompile-apk", "decompile-dex", "decompile-jar",
    "decompile-dotnet", "decompile-il-to-csharp",
    "decompile-python-bytecode", "decompile-pyc",
}

# Capabilities the planner may request mapped to which skill serves them. The
# first matching skill with satisfied prerequisites wins.
_CAP_TO_SKILL: dict[str, str] = {
    # container reveal
    "unpack-archive": "unpack", "extract-recursive": "unpack",
    # deobfuscation
    "deobfuscate-js": "js-deobfuscate", "deobfuscate": "js-deobfuscate",
    "unpack-js-bundle": "js-deobfuscate", "unminify-js": "js-deobfuscate",
    # static string decoding (constant-key XOR/charCode; zero-execution complement to deobfuscate)
    "decode-strings": "js-string-decode", "xor-decode": "js-string-decode",
    # decompilation
    "decompile-jvm": "jvm-decompile", "decompile-apk": "jvm-decompile",
    "decompile-dex": "jvm-decompile", "decompile-jar": "jvm-decompile",
    "decompile-dotnet": "dotnet-decompile", "decompile-il-to-csharp": "dotnet-decompile",
    "decompile-python-bytecode": "pyc-decompile", "decompile-pyc": "pyc-decompile",
    "decompile-native": "bin-triage",  # no native decompiler skill yet; triage only
    # atom emission (binary/source triage)
    "binary-triage": "bin-triage", "triage-binary": "bin-triage",
    "emit-atoms": "bin-triage",
    "detect-js-steganography": "js-covert-scan", "detect-js-obfuscation-tactics": "js-covert-scan",
    "detect-js-evasion": "js-covert-scan",
    "detect-py-obfuscation-tactics": "py-covert-scan", "detect-py-evasion": "py-covert-scan",
    "detect-steganography": "py-covert-scan",
    "scan-secrets": "secrets-scan", "detect-credentials": "secrets-scan",
}

# Subprocess guardrails. Skill runtimes are trusted code; the input is hostile.
_TIMEOUT_S = 1800           # 30 min ceiling (jadx on a big APK can be slow)
_MAX_OUTPUT_BYTES = 8 << 20  # 8 MiB cap on captured stdout/stderr
_ENV_SCRUB_RE = re.compile(
    r"(?:SECRET|TOKEN|KEY|PASSWORD|PASSWD|CREDENTIAL|API|PRIVATE)", re.I,
)


@dataclass
class _ResolvedSkill:
    id: str
    skill_dir: Path
    capabilities: list[str]
    prereqs_ok: bool
    missing_prereqs: list[str]


def _scrub_env(env: dict[str, str]) -> dict[str, str]:
    out = {}
    for k, v in env.items():
        if _ENV_SCRUB_RE.search(k):
            continue
        out[k] = v
    return out


def _version_tuple(s: str) -> tuple[int, ...]:
    """First ``\\d+(\\.\\d+)*`` in ``s`` → a tuple of ints for comparison."""
    m = re.search(r"\d+(?:\.\d+)*", s)
    if not m:
        return ()
    return tuple(int(x) for x in m.group(0).split("."))


def _check_prereq(prereq: dict) -> bool:
    """Run a skill.json prerequisite check: tool on PATH (+ optional min_version)."""
    tool = prereq.get("tool")
    check = prereq.get("check")
    if not tool or not check:
        # A prereq without a check is always satisfied (informational only).
        return True
    try:
        proc = subprocess.run(
            check, capture_output=True, text=True, timeout=15,
            env=_scrub_env(dict(os.environ)))
    except (FileNotFoundError, subprocess.SubprocessError):
        return False
    if proc.returncode != 0 and not proc.stdout and not proc.stderr:
        return False
    out = (proc.stdout or proc.stderr or "").strip()
    min_v = prereq.get("min_version")
    if min_v:
        have = _version_tuple(out)
        need = _version_tuple(str(min_v))
        if have and need and have < need:
            return False
    return True


@lru_cache(maxsize=1)
def _load_manifest() -> dict:
    if not _MANIFEST.is_file():
        return {"schemaVersion": "0.1.0", "skills": []}
    try:
        return json.loads(_MANIFEST.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"schemaVersion": "0.1.0", "skills": []}


@lru_cache(maxsize=1)
def _resolved_skills() -> tuple[_ResolvedSkill, ...]:
    out = []
    for rec in _load_manifest().get("skills", []):
        sid = rec["id"]
        sdir = _SKILLS_DIR / sid
        if not sdir.is_dir():
            continue
        prereqs = rec.get("prerequisites") or []
        missing = [p.get("tool", "?") for p in prereqs if not _check_prereq(p)]
        out.append(_ResolvedSkill(
            id=sid, skill_dir=sdir, capabilities=list(rec.get("capabilities") or []),
            prereqs_ok=not missing, missing_prereqs=missing))
    return tuple(out)


def _capabilities() -> list[str]:
    """Capabilities with ALL prerequisites satisfied — what we can actually do."""
    caps: list[str] = []
    for sk in _resolved_skills():
        if sk.prereqs_ok:
            caps.extend(sk.capabilities)
    # De-duplicate, preserve order.
    seen, out = set(), []
    for c in caps:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def _skill_for(cap: str) -> _ResolvedSkill | None:
    sid = _CAP_TO_SKILL.get(cap)
    if not sid:
        return None
    for sk in _resolved_skills():
        if sk.id == sid and sk.prereqs_ok:
            return sk
    return None


def _parse_skill_result(stdout: str, fallback: dict) -> dict:
    """Skills print one JSON object to stdout as their machine result. Fall back to a
    best-effort parse (some runners print text + a JSON line); never raise."""
    stdout = (stdout or "").strip()
    if not stdout:
        return fallback
    # Try the whole stdout, then the last non-empty line (text-format runners end JSON).
    for candidate in (stdout, stdout.splitlines()[-1] if stdout else ""):
        try:
            obj = json.loads(candidate)
            if isinstance(obj, dict):
                return obj
        except ValueError:
            continue
    return fallback


def _coerce_atoms(obj: dict, origin: str) -> list[EmittedAtom]:
    """Map a skill's atoms/findings array → EmittedAtom. Skills use slightly
    different field names; tolerate both."""
    out: list[EmittedAtom] = []
    raw = obj.get("atoms") or obj.get("findings") or []
    for a in raw:
        if not isinstance(a, dict) or not a.get("atom"):
            continue
        out.append(EmittedAtom(
            atom=str(a["atom"]),
            confidence=float(a.get("confidence", 0.5) or 0.0),
            method=str(a.get("method") or "skill-emit"),
            path=str(a.get("path") or a.get("file") or origin),
            line=a.get("line"),
            evidence=a.get("evidence") or a.get("matched") or a.get("snippet") or a.get("note"),
            rule_id=a.get("rule_id") or a.get("ruleId") or a.get("id"),
            summary=a.get("summary"),
        ))
    return out


@dataclass
class SkillTransformProvider:
    """The skill-driven RE provider registered under ``unmask.providers``.

    Capabilities are prereq-gated: a skill whose external tool (jadx, ilspycmd,
    node, …) is missing advertises nothing, so core reports an honest blind spot
    rather than claiming a capability it can't fulfill. ``transform`` shells out to
    the skill's runner, parses the JSON result, and maps it to the transform seam's
    DerivedSource / EmittedAtom model.
    """

    id: str = "unmask-re.skills"
    capabilities: list[str] = field(default_factory=_capabilities)
    # Report which external tools actually resolved (for the toolchain section).
    tools_available: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        avail = []
        for sk in _resolved_skills():
            if sk.prereqs_ok:
                avail.append(sk.id)
        self.tools_available = avail

    # -- TransformProvider protocol ------------------------------------------------

    def can_handle(self, artifact: ArtifactRef) -> bool:
        kind = artifact.kind
        # Map the artifact kind to the capability the planner would request, then
        # check a skill for it is present AND its prerequisites resolved.
        caps = _kind_to_caps(kind)
        for cap in caps:
            if cap in self.capabilities and _skill_for(cap) is not None:
                return True
        return False

    def transform(self, artifact: ArtifactRef, workdir: str) -> TransformResult | dict:
        caps = [c for c in _kind_to_caps(artifact.kind)
                if c in self.capabilities and _skill_for(c) is not None]
        if not caps:
            return TransformResult.failed(
                self.id, artifact.logical_path, "(none)",
                f"no skill/capability for artifact kind {artifact.kind!r}")
        # Obfuscated source runs ALL applicable passes (deobfuscate + tactics-scan +
        # unminify) and merges their derived source and atoms; every other kind runs the
        # single best skill. Each pass writes to its own subdir so outputs never collide.
        run = caps if artifact.kind == "obfuscated-source" else caps[:1]
        results = [self._run_skill(_skill_for(c), artifact, c,
                                   os.path.join(workdir, f"c{i}-{c}"))
                   for i, c in enumerate(run)]
        if len(results) == 1:
            return results[0]
        derived, atoms, notes = [], [], []
        for r in results:
            derived += list(r.derived)
            atoms += list(r.atoms)
            if r.error:
                notes.append(f"{r.capability}: {r.error}")
            elif r.note:
                notes.append(r.note)
        return TransformResult(provider_id=self.id, artifact=artifact.logical_path,
                               capability=run[0], derived=derived, atoms=atoms,
                               note="; ".join(notes) or None)

    # -- internals -----------------------------------------------------------------

    def _select_capability(self, artifact: ArtifactRef) -> str | None:
        for cap in _kind_to_caps(artifact.kind):
            if cap in self.capabilities and _skill_for(cap) is not None:
                return cap
        return None

    def _run_skill(self, sk: _ResolvedSkill, artifact: ArtifactRef, cap: str,
                   workdir: str) -> TransformResult:
        skill_json_path = sk.skill_dir / "skill.json"
        try:
            manifest = json.loads(skill_json_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return TransformResult.failed(self.id, artifact.logical_path, cap,
                                          f"unreadable skill.json: {exc!r}")
        entry = manifest.get("entry") or {}
        command = entry.get("command") or []
        if not command:
            return TransformResult.failed(self.id, artifact.logical_path, cap,
                                          "skill.json has no entry.command")
        # entry.command is resolved relative to the skill dir (e.g. ["node","runtime/run.mjs"]).
        argv = [_resolve_cmd_part(sk.skill_dir, command[0])] + list(command[1:])
        # Positional args per entry.args: always the input path; append the workdir only
        # when the skill declares a SECOND positional (an outdir). Stdout-only skills
        # (bin-triage, the covert scanners, secrets-scan) declare just `input`, and an
        # extra positional makes their argparse reject the entire call.
        positional_args = [a for a in (entry.get("args") or [])
                           if isinstance(a, dict) and not str(a.get("name", "")).startswith("-")]
        argv.append(str(artifact.path))
        if len(positional_args) >= 2:
            argv.append(str(workdir))
        os.makedirs(workdir, exist_ok=True)
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True, timeout=_TIMEOUT_S,
                env=_scrub_env(dict(os.environ)), cwd=str(sk.skill_dir))
        except subprocess.TimeoutExpired:
            return TransformResult.failed(self.id, artifact.logical_path, cap,
                                          f"skill timed out after {_TIMEOUT_S}s")
        except (FileNotFoundError, OSError) as exc:
            return TransformResult.failed(self.id, artifact.logical_path, cap,
                                          f"skill invocation failed: {exc!r}")
        result = _parse_skill_result(proc.stdout, {
            "ok": proc.returncode == 0, "exitCode": proc.returncode,
            "_stderr": (proc.stderr or "")[:4000],
        })
        if not result.get("ok"):
            err = result.get("error") or result.get("_stderr") or f"exit {proc.returncode}"
            return TransformResult.failed(self.id, artifact.logical_path, cap, str(err)[:1000])

        origin = artifact.logical_path
        method = "unpack" if cap in ("unpack-archive", "extract-recursive") else (
            "deobfuscate" if cap.startswith("deobfuscate") else "decompile")
        derived, atoms = [], []
        # Recovered source roots → DerivedSource (rescanned by the fold).
        for key in ("outputDir", "outputFile", "extractedTo"):
            root = result.get(key)
            if root and Path(root).exists():
                derived.append(DerivedSource(root=str(root), origin=origin, method=method))
        # Directly-emitted atoms → EmittedAtom (folded straight into compose).
        atoms = _coerce_atoms(result, origin=origin)
        note = None
        if not derived and not atoms:
            note = (f"skill {sk.id} reported ok but produced no recoverable source or atoms; "
                    f"result={json.dumps(result)[:300]}")
        return TransformResult(
            provider_id=self.id, artifact=origin, capability=cap,
            derived=derived, atoms=atoms, note=note)


def _resolve_cmd_part(skill_dir: Path, part: str) -> str:
    """Resolve an entry.command part: a bare executable (python3/node) stays as-is
    (found on PATH); a relative path is resolved against the skill dir."""
    # If it's just a bare name (no slash, no path), leave it for PATH lookup.
    if "/" not in part and "\\" not in part:
        return part
    resolved = (skill_dir / part).resolve()
    return str(resolved)


def _kind_to_caps(kind: str) -> tuple[str, ...]:
    """Map an ArtifactRef.kind to the capability strings a skill could serve it,
    best-first. Mirrors the planner's _KIND_CAPS so can_handle()/transform() pick
    the same skill the planner requested."""
    return {
        # Obfuscated JS/TS runs several applicable passes (see transform), each fast except
        # deobfuscate: statically decode constant-key XOR/charCode strings so the concealed
        # payload (URLs, targeting lists, timezone gates) becomes plaintext the scanner reads
        # (decode-strings); recover + prettify the source (deobfuscate-js — webcrack already
        # unminifies, so a separate unminify-js pass is redundant + a 2nd slow webcrack run);
        # and name the concealment/evasion tactics as OBF/EVADE/STEGO atoms
        # (detect-js-obfuscation-tactics, a fast pure-python scan).
        "obfuscated-source": ("decode-strings", "deobfuscate-js",
                              "detect-js-obfuscation-tactics", "deobfuscate"),
        # `triage-binary` is the real bin-triage capability (was mis-named `binary-triage`,
        # which no skill advertises, so native binaries fell through to an honest blind spot
        # even though format-agnostic triage was available).
        "native-binary": ("decompile-native", "triage-binary"),
        "dotnet": ("decompile-dotnet",),
        "jar": ("decompile-jvm",),
        "apk": ("decompile-jvm",),
        "dex": ("decompile-jvm",),
        "jvm-bytecode": ("decompile-jvm",),
        "pyc": ("decompile-python-bytecode",),
        "archive": ("unpack-archive",),
    }.get(kind, ())


# The entry-point loads THIS instance. Capabilities are computed at construction
# (prereq-gated), so a host with no jadx/java/node advertises only the pure-stdlib
# skills (unpack, bin-triage, covert-scans, secrets) — binaries that need a missing
# tool route to an honest blind spot.
provider = SkillTransformProvider()

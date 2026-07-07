"""Decide which artifacts to hand which transform.

Two triggers, each matched against the capabilities a provider actually advertises —
core never requests a transform nothing can service:

  - obfuscated source : a file whose atoms say the real code is hidden — structural
    obfuscation (XFRM.CTRLFLOW/PACK/RENAME/STRCON/STEG) or decode-and-execute
    (LOAD.EVAL co-located with any XFRM). Request ``deobfuscate`` to recover it.
  - binary artifact   : a compiled/packaged file core can't read as source. Request
    the decompiler/unpacker for its kind, falling back to ``binary-triage`` (atoms
    only) when no decompiler is offered.

Requests are de-duplicated against ``done`` so the fixpoint doesn't re-transform the
same artifact each pass.
"""

from __future__ import annotations

from dataclasses import dataclass

from unmask.transform.contract import ArtifactRef

# Atoms that mean "the source you can see is not the source that runs".
_OBF_STRUCTURAL = frozenset({"XFRM.CTRLFLOW", "XFRM.PACK", "XFRM.RENAME", "XFRM.STRCON", "XFRM.STEG"})

# Best-to-worst decompile/unpack capability per binary kind. The engine also accepts
# ``binary-triage``/``emit-atoms`` as a universal fallback (atoms without decompile).
_KIND_CAPS: dict[str, tuple[str, ...]] = {
    "native-binary": ("decompile-native",),
    "jar": ("decompile-jvm", "decompile-jar"),
    "apk": ("decompile-apk", "decompile-jvm"),
    "dex": ("decompile-jvm",),
    "jvm-bytecode": ("decompile-jvm",),
    "pyc": ("decompile-python-bytecode", "decompile-pyc"),
    "dotnet": ("decompile-dotnet",),
    "archive": ("unpack-archive", "extract-recursive"),
}

_DEOBF_BY_LANG: dict[str, tuple[str, ...]] = {
    "javascript": ("deobfuscate-js", "deobfuscate"),
    "typescript": ("deobfuscate-js", "deobfuscate"),
}
_DEOBF_DEFAULT = ("deobfuscate",)
_TRIAGE_FALLBACKS = ("binary-triage", "emit-atoms")


@dataclass(frozen=True)
class TransformRequest:
    artifact: ArtifactRef
    capability: str
    priority: int = 0


def _pick(preferred, capabilities: set[str], *, allow_triage: bool) -> str | None:
    for c in preferred:
        if c in capabilities:
            return c
    if allow_triage:
        for c in _TRIAGE_FALLBACKS:
            if c in capabilities:
                return c
    return None


def _needs_deobfuscation(atoms: set[str]) -> bool:
    if atoms & _OBF_STRUCTURAL:
        return True
    return "LOAD.EVAL" in atoms and any(a.startswith("XFRM.") for a in atoms)


def plan_transforms(observations, inv, *, binary_artifacts, capabilities, done):
    """Build the transform requests for one pass.

    ``inv`` is the scanner Inventory (rel -> FileEntry, for resolving an obfuscated
    file's on-disk path and language). ``binary_artifacts`` is a list of `ArtifactRef`
    the caller assembled from the target tree. ``done`` is the set of logical paths
    already transformed. Returns `TransformRequest`s, highest priority first.
    """
    caps = set(capabilities)
    seen = set(done)
    by_rel = {f.rel: f for f in inv.files}
    requests: list[TransformRequest] = []

    # -- obfuscated source ---------------------------------------------------
    atoms_by_path: dict[str, set[str]] = {}
    for o in observations:
        atoms_by_path.setdefault(o.path, set()).add(o.atom)
    for rel, atoms in atoms_by_path.items():
        if rel in seen or not _needs_deobfuscation(atoms):
            continue
        fe = by_rel.get(rel)
        if fe is None or fe.kind not in ("source", "text"):
            continue
        lang = (fe.language or "").lower()
        cap = _pick(_DEOBF_BY_LANG.get(lang, _DEOBF_DEFAULT), caps, allow_triage=False)
        if cap is None:
            continue
        seen.add(rel)
        requests.append(TransformRequest(
            artifact=ArtifactRef(path=fe.path, logical_path=rel, kind="obfuscated-source",
                                 language=fe.language or None, atoms=tuple(sorted(atoms))),
            capability=cap, priority=20))

    # -- binary artifacts ----------------------------------------------------
    for art in binary_artifacts:
        if art.logical_path in seen:
            continue
        cap = _pick(_KIND_CAPS.get(art.kind, ()), caps, allow_triage=True)
        if cap is None:
            continue
        seen.add(art.logical_path)
        requests.append(TransformRequest(artifact=art, capability=cap, priority=10))

    requests.sort(key=lambda r: -r.priority)
    return requests

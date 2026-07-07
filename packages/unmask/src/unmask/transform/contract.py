"""The transform contract — the stable seam between core and the RE toolset.

An RE provider (wrapped by `unmask-re`, driving the skillpacks toolset) opens up an
artifact core can't read directly: it *deobfuscates* minified/packed source,
*decompiles* a binary back to source, or *unpacks* an exotic container. Whatever it
recovers comes back as a `TransformResult` with two independent, optional channels:

  - ``derived``  : recovered-source roots (dirs/files) core RESCANS — observe →
                   compose — folding the findings back in with provenance. This is
                   how a deobfuscated bundle or decompiled class tree becomes MCD
                   findings using the same rules as first-party source.
  - ``atoms``    : atoms a skill observed DIRECTLY (the skillpacks ``emit-atoms``
                   capability — bin-triage, covert-scan). No source to rescan; core
                   validates the atom's family and folds it straight into compose.

Core never imports `unmask-re`. Providers are duck-typed (`TransformProvider`), and
results are coerced from plain dicts too — so the skillpacks toolset stays fully
decoupled and need not import these classes to satisfy the contract.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

# ---------------------------------------------------------------------------
# What core hands a provider.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ArtifactRef:
    """An artifact core wants a provider to open up.

    ``path`` is the concrete on-disk location the provider reads; ``logical_path`` is
    the provenance label carried through the report (e.g. ``Resources/app.asar!index.js``
    for a member already revealed out of a container). ``atoms`` records what core
    already observed on it — the reason it was selected — so a provider can skip work
    it knows is irrelevant.
    """

    path: str
    logical_path: str
    kind: str  # "obfuscated-source" | "native-binary" | "dotnet" | "jvm" | "pyc" | "archive" | ...
    language: str | None = None
    atoms: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# What a provider hands back.
# ---------------------------------------------------------------------------


@dataclass
class DerivedSource:
    """A recovered-source root to rescan. ``root`` is a dir (or single file) of
    source the provider wrote; ``origin`` is the provenance label prefixed onto every
    rescanned member; ``method`` records how it was recovered."""

    root: str
    origin: str
    method: str = "transform"  # "deobfuscate" | "decompile" | "unpack"


@dataclass
class EmittedAtom:
    """An atom a skill observed directly, no source to rescan. ``path`` is a logical
    location within the artifact (prefixed with the artifact's origin on ingest)."""

    atom: str
    confidence: float
    method: str
    path: str
    line: int | None = None
    evidence: str | None = None
    rule_id: str | None = None
    summary: str | None = None


@dataclass
class TransformResult:
    """The outcome of one provider handling one artifact. ``error`` set (with empty
    ``derived``/``atoms``) means the provider tried and failed — an honest coverage
    note, never a crash."""

    provider_id: str
    artifact: str  # logical_path of the ArtifactRef handled
    capability: str
    derived: list[DerivedSource] = field(default_factory=list)
    atoms: list[EmittedAtom] = field(default_factory=list)
    note: str | None = None
    error: str | None = None

    @property
    def produced_anything(self) -> bool:
        return bool(self.derived or self.atoms)

    @classmethod
    def failed(cls, provider_id: str, artifact: str, capability: str, error: str) -> "TransformResult":
        return cls(provider_id=provider_id, artifact=artifact, capability=capability, error=error)

    # -- coercion: accept a plain dict from a decoupled provider ----------------

    @classmethod
    def coerce(cls, obj: Any, *, provider_id: str, artifact: str, capability: str) -> "TransformResult":
        """Normalise a provider's return value into a TransformResult. Accepts a
        TransformResult as-is, or a plain dict (so a provider that never imported this
        module still satisfies the contract). Anything else is a provider bug and is
        recorded as a failed result rather than raised."""
        if isinstance(obj, cls):
            return obj
        if not isinstance(obj, dict):
            return cls.failed(provider_id, artifact, capability,
                              f"provider returned {type(obj).__name__}, expected TransformResult|dict")
        derived = [_coerce_derived(d) for d in (obj.get("derived") or [])]
        atoms = [_coerce_atom(a) for a in (obj.get("atoms") or [])]
        return cls(
            provider_id=str(obj.get("provider_id") or obj.get("providerId") or provider_id),
            artifact=str(obj.get("artifact") or artifact),
            capability=str(obj.get("capability") or capability),
            derived=[d for d in derived if d is not None],
            atoms=[a for a in atoms if a is not None],
            note=obj.get("note"),
            error=obj.get("error"),
        )


def _coerce_derived(d: Any) -> DerivedSource | None:
    if isinstance(d, DerivedSource):
        return d
    if isinstance(d, dict) and d.get("root"):
        return DerivedSource(root=str(d["root"]), origin=str(d.get("origin") or d["root"]),
                             method=str(d.get("method") or "transform"))
    return None


def _coerce_atom(a: Any) -> EmittedAtom | None:
    if isinstance(a, EmittedAtom):
        return a
    if isinstance(a, dict) and a.get("atom"):
        return EmittedAtom(
            atom=str(a["atom"]), confidence=float(a.get("confidence", 0.5) or 0.0),
            method=str(a.get("method") or "emit-atoms"), path=str(a.get("path") or ""),
            line=a.get("line"), evidence=a.get("evidence"),
            rule_id=a.get("rule_id") or a.get("ruleId"), summary=a.get("summary"))
    return None


# ---------------------------------------------------------------------------
# The provider interface (structural — core never imports the implementation).
# ---------------------------------------------------------------------------


@runtime_checkable
class TransformProvider(Protocol):
    """What an `unmask.providers` entry point must look like to open up artifacts.

    ``capabilities`` are the skillpacks capability strings it offers (``deobfuscate-js``,
    ``decompile-jvm``, ``unpack-archive``, ``emit-atoms``, …). ``can_handle`` is a cheap
    pre-check; ``transform`` does the work and writes any recovered source under
    ``workdir``. Neither should raise — the engine still guards, but a well-behaved
    provider returns ``TransformResult.failed(...)`` on its own errors."""

    id: str
    capabilities: list[str]

    def can_handle(self, artifact: ArtifactRef) -> bool: ...

    def transform(self, artifact: ArtifactRef, workdir: str) -> TransformResult | dict: ...

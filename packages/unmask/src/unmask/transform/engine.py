"""Run transform providers and fold what they recover back into the scan.

One *pass* runs each request against a provider that offers its capability and can
handle the artifact, coercing whatever comes back into a `TransformResult`. The
*fold* then turns those results into new observations — rescanning recovered source
(observe → provenance-prefixed) and ingesting directly-emitted atoms. The graph
drives passes to a fixpoint: recovered source may itself carry obfuscation or a
nested binary, which the next pass re-plans and transforms again.

Nothing here imports `unmask-re`. Providers are duck-typed; a provider that raises
(rather than returning ``TransformResult.failed``) is still caught and recorded as a
coverage note, never allowed to fail the run.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace

from unmask.scanner.observe import observe
from unmask.transform.contract import DerivedSource, TransformResult
from unmask.transform.ingest import ingest_atoms
from unmask.transform.plan import TransformRequest


def _select(providers, capability: str, artifact):
    """First provider offering ``capability`` that will handle ``artifact``. A
    provider without ``can_handle`` is assumed willing; one whose ``can_handle``
    raises is skipped rather than crashed on."""
    for p in providers:
        if capability not in (getattr(p, "capabilities", []) or []):
            continue
        can = getattr(p, "can_handle", None)
        if can is None:
            return p
        try:
            if can(artifact):
                return p
        except Exception:
            continue
    return None


def run_transform_pass(requests, providers, workdir: str) -> list[TransformResult]:
    """Execute one pass of requests. Returns a `TransformResult` per request that
    found a provider (requests with no provider are silently skipped — they were only
    planned because *some* provider advertised the capability, but none would take
    this artifact)."""
    results: list[TransformResult] = []
    for i, req in enumerate(requests):
        prov = _select(providers, req.capability, req.artifact)
        if prov is None:
            continue
        pid = getattr(prov, "id", "re-provider")
        member_dir = os.path.join(workdir, f"t{i}-{req.capability}")
        os.makedirs(member_dir, exist_ok=True)
        try:
            raw = prov.transform(req.artifact, member_dir)
            res = TransformResult.coerce(raw, provider_id=pid,
                                         artifact=req.artifact.logical_path, capability=req.capability)
        except Exception as exc:  # a misbehaving provider, not a missing one
            res = TransformResult.failed(pid, req.artifact.logical_path, req.capability,
                                         f"{type(exc).__name__}: {exc}")
        results.append(res)
    return results


@dataclass
class FoldOutcome:
    observations: list = field(default_factory=list)  # new Observations to accumulate
    files: list = field(default_factory=list)         # new FileEntry to add to inventory
    dataflow: dict = field(default_factory=dict)      # derived intra-file taint, prefixed
    dropped: list = field(default_factory=list)       # atoms rejected on ingest
    notes: list = field(default_factory=list)         # provider errors / coverage notes

    @property
    def produced_observations(self) -> bool:
        return bool(self.observations)


def _rescan_derived(d: DerivedSource, sigs, workdir: str):
    """observe() a recovered-source root and re-tag it with the derived origin so its
    findings carry provenance back to the artifact they came from."""
    reveal_dir = os.path.join(workdir, "rescan-reveal")
    os.makedirs(reveal_dir, exist_ok=True)
    sub_obs, sub_inv = observe(d.root, sigs, reveal_dir=reveal_dir)
    prefix = d.origin
    for o in sub_obs:
        o.path = f"{prefix}!{o.path}"
    files = [replace(f, rel=f"{prefix}!{f.rel}") for f in sub_inv.files]
    dataflow = {f"{prefix}!{k}": v for k, v in (sub_inv.dataflow or {}).items()}
    return sub_obs, files, dataflow


def fold_results(results, *, sigs, known_families, workdir: str) -> FoldOutcome:
    """Turn a pass's results into accumulable observations + inventory."""
    out = FoldOutcome()
    for res in results:
        if res.error:
            out.notes.append({"artifact": res.artifact, "provider": res.provider_id,
                              "capability": res.capability, "error": res.error})
        if res.note:
            out.notes.append({"artifact": res.artifact, "provider": res.provider_id, "note": res.note})
        if res.atoms:
            obs, drop = ingest_atoms(res.atoms, origin=res.artifact,
                                     known_families=known_families, source=res.provider_id)
            out.observations += obs
            out.dropped += drop
        for d in res.derived:
            sub_obs, files, df = _rescan_derived(d, sigs, workdir)
            out.observations += sub_obs
            out.files += files
            out.dataflow.update(df)
    return out

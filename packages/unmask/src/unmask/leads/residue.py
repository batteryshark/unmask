"""Residue: signal the deterministic passes left with no verdict.

The guaranteed catalog covers rules × artifacts; residue is where the artifact carried
signal the catalog didn't turn into a finding — a file whose atoms co-occur across
multiple capability families but composed into no ``BP-*``, or a binary the reveal /
decompile triggers never opened up. This is exactly the surface a lead should look at:
"weird but uncaught." (This is unmask's instantiation of the engine's residue hook — a
consumer supplies its own.)
"""

from __future__ import annotations

# Families that are context, not capability, on their own — a URL or a path literal
# alone is not "signal without a verdict".
_NOISE_FAMILIES = {"ARTF"}


def gather_residue(scan, *, max_items: int = 12) -> list[dict]:
    """Files that produced signal (≥2 capability families co-occurring) but are cited by
    no finding. Highest-signal first, capped. Each entry: {path, atoms, families}."""
    observations = scan.observations
    obs_by_id = {o.get("id"): o for o in observations if o.get("id")}

    cited_paths: set[str] = set()
    for f in scan.findings:
        for eid in f.get("evidence", []) or []:
            o = obs_by_id.get(eid)
            path = ((o or {}).get("location") or {}).get("path")
            if path:
                cited_paths.add(path)

    atoms_by_path: dict[str, set[str]] = {}
    for o in observations:
        path = (o.get("location") or {}).get("path")
        atom = o.get("atom")
        if path and atom:
            atoms_by_path.setdefault(path, set()).add(atom)

    residue: list[dict] = []
    for path, atoms in atoms_by_path.items():
        if path in cited_paths:
            continue
        families = {a.split(".", 1)[0] for a in atoms}
        if len(families - _NOISE_FAMILIES) >= 2:  # real co-occurrence that didn't compose
            residue.append({"path": path, "atoms": sorted(atoms), "families": sorted(families)})

    residue.sort(key=lambda r: (-len(r["atoms"]), r["path"]))
    return residue[:max_items]

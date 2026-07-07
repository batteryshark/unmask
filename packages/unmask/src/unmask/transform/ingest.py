"""Fold a provider's emitted atoms into the observation stream.

RE skills that carry the skillpacks ``emit-atoms`` capability speak the same atom
vocabulary the scanner composes into BP-* findings. Ingestion turns those records
into `Observation`s so they flow into compose exactly like a first-party callee hit —
after validating the atom against the taxonomy's families. An atom in an unknown
family (or malformed) can't compose into anything, so it is dropped with a recorded
reason rather than injected as silent noise.
"""

from __future__ import annotations

import re
from dataclasses import asdict

from unmask.scanner.observe.atoms import Observation
from unmask.transform.contract import EmittedAtom

# FAMILY.SUBTYPE, e.g. XFRM.OBFUSCATE. Family is validated against the taxonomy;
# the subtype is intentionally open so a skill may emit a newer subtype in a known
# family without core gatekeeping it.
_ATOM_RE = re.compile(r"^[A-Z]{2,6}\.[A-Z0-9_]+$")


def _as_dict(rec) -> dict:
    if isinstance(rec, EmittedAtom):
        return asdict(rec)
    return dict(rec) if isinstance(rec, dict) else {}


def ingest_atoms(records, *, origin: str, known_families, source: str = "re-provider"):
    """Turn emitted-atom records into Observations tagged with ``origin`` provenance.

    Returns ``(observations, dropped)``. ``dropped`` is a list of ``{atom, reason}``
    for records that failed validation, surfaced by the caller as an honest coverage
    note. Confidence is clamped to [0,1]; a missing path falls back to ``origin`` so
    the atom is still locatable.
    """
    observations: list[Observation] = []
    dropped: list[dict] = []
    fams = set(known_families)
    for rec in records:
        d = _as_dict(rec)
        atom = str(d.get("atom") or "").strip().upper()
        if not _ATOM_RE.match(atom):
            dropped.append({"atom": atom or "(empty)", "reason": "malformed-atom", "origin": origin})
            continue
        if atom.split(".", 1)[0] not in fams:
            dropped.append({"atom": atom, "reason": "unknown-family", "origin": origin})
            continue
        try:
            conf = float(d.get("confidence", 0.5) or 0.0)
        except (TypeError, ValueError):
            conf = 0.5
        conf = min(1.0, max(0.0, conf))
        member = str(d.get("path") or "").strip()
        path = f"{origin}!{member}" if (origin and member) else (member or origin)
        line = d.get("line")
        observations.append(Observation(
            atom=atom, confidence=conf,
            method=str(d.get("method") or source),
            path=path, line=int(line) if isinstance(line, int) else None,
            rule_id=d.get("rule_id"), evidence=d.get("evidence"),
            summary=d.get("summary"),
        ))
    return observations, dropped

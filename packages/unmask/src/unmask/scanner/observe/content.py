"""Content-atom extraction: run the content-surface pack over file text.

Uses the slice-1 matcher (`Signatures.classify_content`). This is the string
evidence layer — atoms whose method is ``content-regex`` (weaker than a proven
call site, so compose/assess attenuate accordingly).
"""

from __future__ import annotations

from pathlib import Path

from unmask.scanner.observe.atoms import Observation
from unmask.scanner.observe.inventory import Inventory
from unmask.scanner.signatures import Signatures

_MAX_BYTES = 2_000_000  # skip absurdly large files for the text pass


def observe_content(inv: Inventory, sigs: Signatures | None = None) -> list[Observation]:
    sigs = sigs or Signatures.load_vendored()
    out: list[Observation] = []
    for f in inv.scannable():
        if f.size > _MAX_BYTES:
            continue
        try:
            text = Path(f.path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lang = f.language or "*"
        for hit in sigs.classify_content(text, lang):
            line = text.count("\n", 0, hit.start) + 1 if hit.start is not None else None
            out.append(Observation(
                atom=hit.atom, confidence=hit.confidence, method="content-regex",
                path=f.rel, line=line, rule_id=hit.rule_id, evidence=hit.text,
            ))
    return out

"""Native signature-pack reader + matcher — slice 1 of the scanner rebuild.

Consumes the vendored `parallax-signature-pack/v1` packs (callee / content /
binary-import surfaces) uniformly. The old engine only pack-drove the callee
surface and hardcoded content detection in `rules.py`; this reads every surface
from data, which is the whole point of the taxonomy/engine split.

The matcher reproduces the reference semantics (engine `signatures._matches`)
exactly, so callee classification is parity-locked against the old engine — see
tests/test_signatures.py. Meaning lives in the packs; mechanics live here.
"""

from __future__ import annotations

from unmask.scanner.signatures.loader import Signatures, load_pack, vendored_packs_dir
from unmask.scanner.signatures.matcher import match_symbol, normalize
from unmask.scanner.signatures.models import ContentRule, Hit, MatchRule, SignaturePack

__all__ = [
    "Signatures", "load_pack", "vendored_packs_dir",
    "match_symbol", "normalize",
    "ContentRule", "Hit", "MatchRule", "SignaturePack",
]

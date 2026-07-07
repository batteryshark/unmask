"""Compose — turn judgment-free atoms into BP-* malicious-code findings (slice 3).

The interpretive layer above observe: `compose_mcd(observations, inventory)` runs
the MCD reading (BP-SUPPLY / BP-OBFEXEC / BP-DROPPER / …). Severity is a shape
property; confidence is separate; every finding states what would disprove it.
"""

from __future__ import annotations

from unmask.scanner.compose.mcd import mcd as compose_mcd

__all__ = ["compose_mcd"]

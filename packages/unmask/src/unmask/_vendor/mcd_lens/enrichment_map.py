"""mcd's enrichment-to-composition mapping.

The engine derives enrichment facts (install-phase, unlocked dependency, native
drift, ...) that adjust finding confidence by their atom families. That mechanism
is product-neutral and lives in the engine. WHICH mcd compositions each fact is
relevant to is mcd content, so the map lives here; the mcd assessment passes it to
`enrichment.derive(report, composition_map=COMPOSITIONS_BY_FACT)` so each fact also
names the BP-* compositions it touches. It is presentational metadata only: the
confidence math keys off atom families, never this map.
"""

from __future__ import annotations

from mcd_lens.readings import MCD_COMPOSITIONS

_ALL_MCD_COMPOSITIONS = list(MCD_COMPOSITIONS)

COMPOSITIONS_BY_FACT = {
    "ENR.EXEC.PHASE": [
        "BP-SUPPLY", "BP-DROPPER", "BP-CREDTHEFT", "BP-OBFEXEC",
        "BP-BACKDOOR", "BP-EXFIL", "BP-RANSOM", "BP-TIMEBOMB",
        "BP-MINER", "BP-ROOTKIT", "BP-WORM", "BP-TROJAN",
        "BP-LATERAL", "BP-MITM",
    ],
    "ENR.DEP.RESOLUTION": [
        "BP-SUPPLY", "BP-TYPOSQUAT", "BP-DROPPER", "BP-OBFEXEC",
        "BP-TROJAN", "BP-AGENTMANIP",
    ],
    "ENR.DRIFT.NATIVE": [
        "BP-DROPPER", "BP-OBFEXEC", "BP-BACKDOOR", "BP-ROOTKIT",
        "BP-TROJAN", "BP-MINER", "BP-MITM",
    ],
    "ENR.DEP.NO_LOCKFILE": _ALL_MCD_COMPOSITIONS,
    "ENR.DEP.UNLOCKED": _ALL_MCD_COMPOSITIONS,
    "ENR.DEP.LOCKED": _ALL_MCD_COMPOSITIONS,
    "ENR.DEP.SOURCE": [
        "BP-SUPPLY", "BP-TYPOSQUAT", "BP-DROPPER", "BP-OBFEXEC",
        "BP-BACKDOOR", "BP-TROJAN", "BP-AGENTMANIP",
    ],
    "ENR.PKG.UNPINNED": _ALL_MCD_COMPOSITIONS,
    "ENR.PKG.UNKNOWN_VERSION": _ALL_MCD_COMPOSITIONS,
}

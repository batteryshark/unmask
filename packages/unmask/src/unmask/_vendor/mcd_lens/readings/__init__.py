"""mcd product readings and the composition list they emit.

The mcd reading turns product-neutral observations (from the engine) into BP-*
malicious-code compositions. `MCD_COMPOSITIONS` is the authoritative list of the
composition ids this product implements; it used to live in the engine's shared
`interpret.common`, but compositions are product content, so it moved here.
"""

from __future__ import annotations

MCD_COMPOSITIONS = [
    "BP-SUPPLY", "BP-TYPOSQUAT", "BP-DROPPER", "BP-CREDTHEFT", "BP-OBFEXEC",
    "BP-BACKDOOR", "BP-EXFIL", "BP-RANSOM", "BP-TIMEBOMB", "BP-MINER",
    "BP-ROOTKIT", "BP-WORM", "BP-TROJAN", "BP-AGENTMANIP", "BP-LATERAL",
    "BP-MITM",
]

"""unmask-re — reverse-engineering providers for the unmask core.

Presence of this package (discovered via the `unmask.providers` entry point) is
what flips binary artifacts from "unanalysed blind spot" to "deeply analysed".
"""

from __future__ import annotations

from unmask_re.provider import provider

__all__ = ["provider"]
__version__ = "0.0.1"

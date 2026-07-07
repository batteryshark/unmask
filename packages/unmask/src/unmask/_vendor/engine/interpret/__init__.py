"""The interpret library: readings that turn observations into findings.

A "lens" is taxonomy nomenclature for one of these readings, not a first-class
registered engine object. v2 dropped the public LENSES registry and the
user-facing --lens selector: products import the readings they need and compose
them. The engine keeps only the SHARED `capability` reading (the neutral
capability-surface layer many products read); READINGS is that one-entry map,
and engine.run_readings composes whatever reading callables a product hands it.

Shared primitives live in common.py. Product-specific readings (a product's
malicious-code reading, for instance) live with their product, not here.
"""

from .common import (  # noqa: F401
    highest_severity,
    _SEV_RANK,
    _CAP_SURFACES,
)
from .capability import capability as read_capability

READINGS = {
    "capability": read_capability,
}

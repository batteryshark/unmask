"""Optional deep static-analysis providers.

These providers run after the broad native scan has selected a behavior that needs
more evidence. They enrich the native inventory; they do not create MCD findings.
"""

from unmask.scanner.deep.joern import (
    DeepStaticResult,
    RekitJoernProvider,
    analyze_with_joern,
    apply_joern_result,
)

__all__ = [
    "DeepStaticResult",
    "RekitJoernProvider",
    "analyze_with_joern",
    "apply_joern_result",
]

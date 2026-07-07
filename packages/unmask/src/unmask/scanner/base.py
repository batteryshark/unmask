"""Scanner protocol + result types."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


class ScannerUnavailable(RuntimeError):
    """Raised when the deterministic scanner (engine + mcd_lens) can't be resolved.

    This is an honest failure, not a silent skip: the run is marked accordingly
    and the report says the static reading could not be produced.
    """


@dataclass
class ScanResult:
    observations: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    assessment: dict = field(default_factory=dict)
    rendered: dict = field(default_factory=dict)  # {"html": str, "md": str, "json": str}
    scanner_meta: dict = field(default_factory=dict)


@runtime_checkable
class Scanner(Protocol):
    def scan(self, target: str) -> ScanResult: ...

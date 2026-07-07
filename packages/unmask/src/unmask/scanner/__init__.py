"""Scanner adapter surface.

The deterministic MCD reading + report is owned by the parallax scanner
(engine + mcd_lens). Core treats it behind a small `Scanner` protocol so the
graph never imports engine internals directly, and so a vendored copy can later
replace the path-resolved checkout with no node changes.
"""

from __future__ import annotations

from unmask.scanner.base import ScannerUnavailable, ScanResult
from unmask.scanner.native import NativeScanner

__all__ = ["NativeScanner", "ScanResult", "ScannerUnavailable"]

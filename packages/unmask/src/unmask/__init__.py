"""unmask — Malicious Code Detection (core).

A durable, graph-driven MCD tool. The phase graph controls the workflow; a SQLite
work ledger controls coverage and resumability; the deterministic parallax scanner
(engine + mcd_lens) performs the actual reading and owns the report contract.

Public API (stable surface):

    from unmask import run_mcd, MCDConfig
    result = run_mcd("./target", MCDConfig(storage_root=".mcd"))
    print(result.report_paths["html"])
"""

from __future__ import annotations

from unmask.config import MCDConfig
from unmask.run import RunResult, run_mcd

__all__ = ["MCDConfig", "RunResult", "run_mcd"]
__version__ = "0.0.1"

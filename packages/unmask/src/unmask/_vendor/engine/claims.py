"""Documentation-versus-behavior contradiction (AITM.CONTEXT).

When a package's own stated scope claims a narrow capability ("offline",
"no eval", "read-only") that the observed atoms directly contradict, the
documentation describes a narrower scope than the code actually has. This is a
factual mismatch, not a judgment: the doc claims X, the code does Y, and Y is
broader than X. It is the heart of "can I trust code I did not write?" -- the
README says safe, the behavior says otherwise.

Pure-Python, cross-platform: it reads `inv.purpose` (the lowercased manifest
description / tagline the curiosity lens already builds) and the observation set.
Scoped to the prominent claim surface (description / tagline), which keeps it
low false-positive: a contradiction in the stated tagline is the strongest signal.
"""

from __future__ import annotations

from .model import Observation

# (claim phrases, contradicting atom prefixes, excluded prefixes, behavior label)
_CLAIMS = [
    (("offline", "no network", "without network", "local-only", "local only",
      "no internet", "does not connect", "no telemetry", "no tracking",
      "does not send", "no data collection", "without sending"),
     ("NETW.",), ("NETW.IPC",), "network access"),
    (("no eval", "without eval", "no code execution", "does not execute",
      "no dynamic code", "no arbitrary code"),
     ("LOAD.EVAL", "LOAD.CODEGEN", "EXEC.SHELL", "EXEC.PROC", "EXEC.INJECT", "EXEC.SYSCALL"),
     (), "code execution"),
    (("read-only", "read only", "does not write", "does not modify files",
      "never writes"),
     ("FSYS.WRITE", "FSYS.DELETE"), (), "filesystem writes"),
]


def analyze(inv, observations) -> list:
    """AITM.CONTEXT observations where a stated scope claim is contradicted by an
    observed capability atom. One per contradicted claim, citing the atom."""
    purpose = (getattr(inv, "purpose", "") or "")
    if not purpose:
        return []
    out, seen = [], set()
    for phrases, prefixes, excludes, label in _CLAIMS:
        claim = next((p for p in phrases if p in purpose), None)
        if not claim or label in seen:
            continue
        hit = next((o for o in observations
                    if any(o.atom.startswith(p) for p in prefixes)
                    and not any(o.atom.startswith(x) for x in excludes)), None)
        if not hit:
            continue
        seen.add(label)
        out.append(Observation(
            atom="AITM.CONTEXT", method="static-source", confidence=0.7,
            path=hit.path, start_line=hit.start_line,
            summary=(f'stated scope claims "{claim}" but the code performs {label} '
                     f"({hit.atom}); the documentation describes a narrower scope than "
                     f"the observed behavior"),
            matched_text=claim, rule_id="claims.context"))
    return out

"""The judgment-free observation (atom instance)."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Observation:
    """One atom observed at a location. No judgment — just "this code can do X,
    here's the evidence and how sure we are."

    `method` records how it was seen (e.g. ``content-regex``, ``source-callee``,
    ``manifest``), which drives later confidence attenuation (string-only evidence
    is weaker than a proven call site).
    """
    atom: str
    confidence: float
    method: str
    path: str
    line: int | None = None
    rule_id: str | None = None
    evidence: str | None = None
    summary: str | None = None
    relationships: list[dict] = field(default_factory=list)
    id: str | None = None

    def key(self) -> tuple:
        """Stable identity for dedup (atom at a location from a rule)."""
        return (self.atom, self.path, self.line, self.rule_id, self.method)

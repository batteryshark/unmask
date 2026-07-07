"""Core data structures. Kept deliberately small; they serialize to the
schemas in schemas/ (observation.schema.json, finding.schema.json)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


def confidence_label(c: float) -> str:
    if c >= 0.75:
        return "high"
    if c >= 0.45:
        return "medium"
    return "low"


@dataclass
class Observation:
    atom: str
    method: str
    confidence: float
    path: str
    summary: str
    rule_id: str
    start_line: Optional[int] = None
    matched_text: Optional[str] = None
    idiom: Optional[str] = None
    relationships: list = field(default_factory=list)
    id: Optional[str] = None

    def to_dict(self, scanner: str, version: str, ts: str) -> dict:
        loc = {"path": self.path}
        if self.start_line:
            loc["startLine"] = self.start_line
        ev = {"summary": self.summary}
        if self.matched_text:
            ev["matchedText"] = self.matched_text[:200]
        d = {
            "id": self.id,
            "atom": self.atom,
            "method": self.method,
            "confidence": round(self.confidence, 2),
            "location": loc,
            "evidence": ev,
            "relationships": self.relationships,
            "provenance": {
                "ruleId": self.rule_id,
                "scanner": scanner,
                "scannerVersion": version,
                "timestamp": ts,
            },
        }
        if self.idiom:
            d["idiom"] = self.idiom
        return d

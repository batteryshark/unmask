"""NativeScanner: the self-contained native pipeline behind the Scanner protocol.

    observe(target) -> compose_mcd -> build_assessment -> render {html,md,json}

No `_vendor` engine, no external checkout — this is the rebuilt scanner. Returns
the same `ScanResult` the graph consumes, so it drops in for `ParallaxScanner`.
"""

from __future__ import annotations

from unmask.scanner.assess import build_assessment, render_html, render_json, render_markdown
from unmask.scanner.base import ScanResult
from unmask.scanner.compose import compose_mcd
from unmask.scanner.observe import extraction_mode, observe


def _normalize_observation(o) -> dict:
    return {
        "id": o.id,
        "atom": o.atom,
        "confidence": float(o.confidence or 0.0),
        "method": o.method or "",
        "rule_id": o.rule_id,
        "location": {"path": o.path, "line": o.line},
        "evidence": o.evidence,
        "relationships": list(o.relationships or []),
    }


class NativeScanner:
    def scan(self, target: str, *, reveal_dir=None) -> ScanResult:
        observations, inv = observe(target, reveal_dir=reveal_dir)
        findings = compose_mcd(observations, inv)
        assessment = build_assessment(findings, observations, inv, target)
        rendered = {
            "html": render_html(assessment),
            "md": render_markdown(assessment),
            "json": render_json(assessment),
        }
        for f in findings:
            f.setdefault("_composition", f.get("composition"))
        return ScanResult(
            observations=[_normalize_observation(o) for o in observations],
            findings=findings,
            assessment=assessment,
            rendered=rendered,
            scanner_meta={"scanner": "unmask-native", "extractionMode": extraction_mode()},
        )

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
    """The native pipeline, exposed both as one-shot `scan()` and as the two halves
    the graph drives around the transform fixpoint: `observe()` produces the atom
    stream, then `compose_assess_render()` runs *once* over the final (post-transform)
    union so finding ids and evidence links stay consistent."""

    def observe(self, target: str, *, reveal_dir=None, sigs=None):
        """Observe atoms over the target (+ stdlib container reveal). Returns the raw
        `(observations, inventory)` so a caller can accumulate transform-derived atoms
        before composing."""
        return observe(target, sigs, reveal_dir=reveal_dir)

    def compose_assess_render(self, observations, inv, target: str) -> ScanResult:
        findings = compose_mcd(observations, inv)
        # Contextual attenuation is an interpretation layer OVER judgment-free
        # composition: documented installer idioms (curl … astral.sh/uv/install.sh | sh)
        # and CI/Dockerfile contexts attenuate confidence so a benign repo doesn't
        # auto-quarantine. Runs here (not inside compose_mcd) so the compose oracle
        # stays judgment-free and the parity tests pin the unattenuated shape.
        from unmask.scanner.compose.attenuators import apply_contextual_attenuators
        apply_contextual_attenuators(findings, observations, inv=inv)
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

    def scan(self, target: str, *, reveal_dir=None) -> ScanResult:
        observations, inv = self.observe(target, reveal_dir=reveal_dir)
        return self.compose_assess_render(observations, inv, target)

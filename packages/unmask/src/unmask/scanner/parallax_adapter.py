"""ParallaxScanner: wrap engine + mcd_lens behind the Scanner protocol.

The whole deterministic MCD pipeline is ~10 lines (mirrors
parallax-goalpacks/skills/mcd-report/scripts/report.py):

    observations, inv = engine.observe(target)
    findings          = mcd_reading(observations, inv)
    report            = engine.report.build(target, ["mcd"], inv, observations,
                                             findings, started, rules.ast_mode())
    assessment        = build_assessment(report)
    render_html / render_markdown / to_json

The scanner (parallax `engine` + `mcd_lens`, both pure stdlib) is vendored into
this wheel under `_vendor/`, and the taxonomy signature data under
`taxonomy/vendored/`, so core is self-contained with nothing to resolve. A
`$UNMASK_SCANNER_ROOT` / upward-search fallback is kept purely as a dev override
for hacking against a live `parallax-goalpacks` checkout.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from unmask.scanner.base import ScannerUnavailable, ScanResult

# `src/unmask` — parent of the `scanner/` package this file lives in.
_UNMASK_PKG = Path(__file__).resolve().parents[1]
_VENDOR_ROOT = _UNMASK_PKG / "_vendor"
_VENDORED_TAXONOMY = _UNMASK_PKG / "taxonomy" / "vendored"
_TAXONOMY_MARKER = os.path.join("signatures", "schema.json")


def _is_scanner_root(c: Path) -> bool:
    return (c / "engine" / "__init__.py").is_file() and (c / "mcd_lens" / "__init__.py").is_file()


def _resolve_scanner_root(configured: str) -> Path:
    """Find a dir containing importable `engine` and `mcd_lens` packages.

    The packaged `_vendor/` copy shipped in the wheel wins. `$UNMASK_SCANNER_ROOT`
    (or a configured root / sibling `parallax-goalpacks`) is only a dev override
    consulted after the vendored copy, for working against a live checkout.
    """
    # 1) Packaged vendored copy — the self-contained default.
    if _is_scanner_root(_VENDOR_ROOT):
        return _VENDOR_ROOT.resolve()

    # 2) Dev override fallbacks.
    candidates: list[Path] = []
    if configured and configured != "auto":
        candidates.append(Path(configured))
    env = os.environ.get("UNMASK_SCANNER_ROOT")
    if env:
        candidates.append(Path(env))
    here = Path.cwd()
    for base in [here, *here.parents]:
        candidates.append(base / "parallax-goalpacks")

    for c in candidates:
        c = c.expanduser()
        if _is_scanner_root(c):
            return c.resolve()
    raise ScannerUnavailable(
        "Could not resolve the parallax scanner (engine + mcd_lens). The wheel "
        "ships a vendored copy under _vendor/; if that is missing, set "
        "UNMASK_SCANNER_ROOT or config.scanner_root to a parallax-goalpacks checkout."
    )


def _normalize_observation(o) -> dict:
    g = lambda name, default=None: getattr(o, name, default)
    path = g("path")
    return {
        "id": g("id"),
        "atom": g("atom"),
        "confidence": float(g("confidence", 0.0) or 0.0),
        "method": g("method", "") or "",
        "rule_id": g("rule_id") or g("rule"),
        "location": {"path": path, "line": g("line")},
        "evidence": g("evidence"),
        "relationships": list(g("relationships", []) or []),
    }


def _finding_composition(f: dict) -> str | None:
    for k in ("composition", "badPattern", "bp", "pattern"):
        v = f.get(k)
        if isinstance(v, str) and v:
            return v
    comps = f.get("compositions")
    if isinstance(comps, list) and comps:
        return comps[0]
    return None


class ParallaxScanner:
    def __init__(self, scanner_root: str = "auto"):
        self.root = _resolve_scanner_root(scanner_root)
        # Point the engine at the wheel's vendored taxonomy signatures so it
        # resolves without any sibling parallax-taxonomy checkout. `setdefault`
        # keeps an explicit dev-set PRLX_TAXONOMY_ROOT authoritative.
        if (_VENDORED_TAXONOMY / _TAXONOMY_MARKER).is_file():
            os.environ.setdefault("PRLX_TAXONOMY_ROOT", str(_VENDORED_TAXONOMY.resolve()))
        if str(self.root) not in sys.path:
            sys.path.insert(0, str(self.root))
        try:
            from engine import engine as eng, report as report_mod, rules  # type: ignore
            from mcd_lens import (  # type: ignore
                mcd_reading, build_assessment, render_html, render_markdown, to_json,
            )
        except Exception as exc:  # pragma: no cover - env dependent
            raise ScannerUnavailable(f"Failed to import engine/mcd_lens from {self.root}: {exc}") from exc
        self._eng = eng
        self._report = report_mod
        self._rules = rules
        self._mcd_reading = mcd_reading
        self._build_assessment = build_assessment
        self._render_html = render_html
        self._render_markdown = render_markdown
        self._to_json = to_json

    def scan(self, target: str) -> ScanResult:
        started = datetime.now(timezone.utc).isoformat()
        observations, inv = self._eng.observe(target)
        findings = self._mcd_reading(observations, inv)
        report = self._report.build(
            target, ["mcd"], inv, observations, findings, started, self._rules.ast_mode(),
        )
        assessment = self._build_assessment(report)
        rendered = {
            "html": self._render_html(assessment),
            "md": self._render_markdown(assessment),
            "json": self._to_json(assessment),
        }
        norm_obs = [_normalize_observation(o) for o in observations]
        for f in findings:
            f.setdefault("_composition", _finding_composition(f))
        return ScanResult(
            observations=norm_obs,
            findings=list(findings),
            assessment=assessment,
            rendered=rendered,
            scanner_meta={"scannerRoot": str(self.root), "astMode": bool(self._rules.ast_mode())},
        )

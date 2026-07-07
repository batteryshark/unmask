"""Parallax MCD lens: the malicious-code reading + assessment layer.

This package is the product half of the MCD pipeline. It sits on top of the
deterministic, product-neutral `engine` (the vendored parallax scanner): the engine
observes what code *can do* (judgment-free atoms), and this lens turns those
observations into BP-* malicious-code compositions (`mcd_reading`) and projects a
scan report onto the malicious-code question (`build_assessment` -> `render_html` /
`render_markdown` / `to_json`).

Public API:
- `mcd_reading(obs, inv=None) -> list`  -- observations to mcd findings.
- `build_assessment(report, lens="mcd") -> dict`  -- scan report to assessment.
- `render_html(assessment) -> str`, `render_markdown(assessment) -> str`.
- `to_json(assessment) -> str`.

The reading and assessment are deterministic: no LLM, no network. (The old
model-authored prose overlay -- brief/polish -- is intentionally not vendored.)
"""

from __future__ import annotations

from mcd_lens.readings.mcd import mcd as mcd_reading
from mcd_lens.assess import build_assessment, render_html, render_markdown, to_json

__all__ = ["mcd_reading", "build_assessment", "render_html", "render_markdown", "to_json"]

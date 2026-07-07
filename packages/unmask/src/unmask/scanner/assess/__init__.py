"""Assess — project native observations + findings into an MCD assessment.

The deterministic disposition (clear / review / quarantine) with severity and
confidence kept separate, correlations over co-located findings, and the coverage
contract. `build_assessment(findings, observations, inventory, target)` returns the
assessment dict; rendering (json/md/html) is the reporter's job.
"""

from __future__ import annotations

from unmask.scanner.assess.build import build_assessment
from unmask.scanner.assess.render import render_html, render_json, render_markdown

__all__ = ["build_assessment", "render_html", "render_json", "render_markdown"]

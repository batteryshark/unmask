"""HTML report polish — TOC, filter chips, syntax highlighting, collapsibles, XSS.

The pretty HTML report is the user-facing artifact; these tests pin the contract:
every feature the design calls for is present, attacker-controlled evidence can
never inject markup, and the report stays self-contained (inline CSS/JS only, no
external resources).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

FIXTURE = Path(__file__).parent / "fixtures" / "evil-npm"


def _scan_html(tmp_path: Path) -> str:
    from unmask import MCDConfig, run_mcd
    result = run_mcd(str(FIXTURE), MCDConfig(storage_root=str(tmp_path / ".mcd")))
    return Path(result.report_paths["html"]).read_text()


def test_html_has_table_of_contents(tmp_path):
    """A TOC with anchor links to disposition / findings / severity groups /
    correlations / coverage makes a long report navigable."""
    h = _scan_html(tmp_path)
    assert "class='toc'" in h or 'class="toc"' in h
    assert "#findings" in h or "id='findings'" in h


def test_html_has_severity_filter_chips(tmp_path):
    """Severity filter chips let the user toggle severity groups on/off."""
    h = _scan_html(tmp_path)
    assert "class='fchip" in h or 'class="fchip' in h
    assert "data-sev" in h


def test_html_has_syntax_highlighting(tmp_path):
    """Evidence <pre> blocks carry token-highlight spans (tok-*) so code reads like
    code, not a wall of monospace."""
    h = _scan_html(tmp_path)
    assert "tok-" in h


def test_html_collapsible_cards_on_large_groups(tmp_path):
    """When a severity group has many findings, cards collapse (details/summary) so
    the report isn't overwhelming; small groups stay expanded by default."""
    h = _scan_html(tmp_path)
    # evil-npm produces multiple findings per group → at least some collapsible.
    assert "details class='card'" in h or "<details" in h


def test_html_is_xss_safe(tmp_path):
    """Attacker-controlled evidence text (matchedText can contain anything) must
    never produce unescaped HTML. Inject a fixture-like payload and verify."""
    from unmask.scanner.assess.highlight import highlight
    import html as html_mod
    # The highlighter runs on ALREADY-escaped text and only inserts <span> tags.
    evil = html_mod.escape('<script>alert("xss")</script> // "injection"')
    result = highlight(evil, "javascript")
    assert "<script>alert" not in result  # no raw script tag
    assert "&lt;script&gt;" in result      # the text stays escaped
    # The full report must also have no raw injected script.
    h = _scan_html(tmp_path)
    assert "<script>alert" not in h


def test_html_is_self_contained(tmp_path):
    """No external stylesheets, fonts, CDNs, or script srcs — the report renders
    offline and doesn't leak the target path to third parties."""
    h = _scan_html(tmp_path)
    h_lower = h.lower()
    assert "src='http" not in h_lower and 'src="http' not in h_lower
    assert "href='http" not in h_lower and 'href="http' not in h_lower
    assert "<link" not in h_lower  # no external stylesheet links


def test_html_has_inline_script_only_for_filters(tmp_path):
    """The only JS is a tiny inline filter-toggle script (no external src)."""
    h = _scan_html(tmp_path)
    assert "<script>" in h
    assert "<script src=" not in h

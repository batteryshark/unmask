"""Content-atom extraction: run the content-surface pack over file text.

Uses the slice-1 matcher (`Signatures.classify_content`). This is the string
evidence layer — atoms whose method is ``content-regex`` (weaker than a proven
call site, so compose/assess attenuate accordingly).

Two post-filters suppress the most common false-positive shapes:

  * **CRED blocklist patterns** — credential filenames (``id_rsa``, ``.npmrc``)
    that appear inside a ``new Set(["id_rsa", ...])`` exclusion-set literal are
    *protection patterns*, not credential reads. The blocklist is the opposite of
    theft; matching it as CRED is a semantic inversion.
  * **TextMate/VS Code grammar files** — language grammar definitions
    (``bat-BSseGlJ2.js``, ``shell-syntax.js``) contain example commands
    (``ipconfig``, ``nslookup``, ``runas``) as syntax-highlighting data, not
    executable code. They are skipped entirely.
"""

from __future__ import annotations

import re
from pathlib import Path

from unmask.scanner.observe.atoms import Observation
from unmask.scanner.observe.inventory import Inventory
from unmask.scanner.signatures import Signatures

_MAX_BYTES = 2_000_000  # skip absurdly large files for the text pass

# A credential/name appearing inside a Set, array, or object-literal exclusion list
# is a blocklist, not a credential read. Matches patterns like:
#   new Set(["id_rsa", ".npmrc", ".env"])
#   ["id_rsa", "id_ed25519", ".env"]
#   excludeList = [".npmrc", "id_rsa"]
# The window is ±120 chars around the match; if a Set/array literal bracket pair
# encloses the match, it's a blocklist entry.
_BLOCKLIST_WINDOW = 120
_BLOCKLIST_RE = re.compile(
    r"(?:new\s+Set\s*\(\s*\[|\[)\s*"
    r"(?:['\"][\w./_-]+['\"]\s*,?\s*){0,20}"
    r"['\"]"  # the opening quote of the matched entry is just before our hit
)


def _is_in_blocklist(text: str, match_start: int, match_end: int) -> bool:
    """Is this CRED match inside a Set([...]) / array-literal exclusion list?

    Looks backward from the match for an opening ``[`` preceded by ``Set(`` or an
    assignment, where the segment between ``[`` and the match contains ONLY
    string-literal entries (quoted names separated by commas). A code expression
    (function call, operator) in that segment means it's NOT a static blocklist.
    """
    window_start = max(0, match_start - _BLOCKLIST_WINDOW)
    before = text[window_start:match_start]
    bracket_idx = before.rfind("[")
    if bracket_idx < 0:
        return False
    segment = before[bracket_idx + 1:]
    pre_bracket = before[:bracket_idx].rstrip()
    # Must be preceded by Set( or an assignment (=), not a random array access.
    is_set = pre_bracket.endswith("Set(") or pre_bracket.endswith("Set (")
    is_assigned = bool(re.search(r"=\s*$", pre_bracket))
    if not (is_set or is_assigned):
        return False
    # The segment between `[` and our match must be all string-literal entries:
    # whitespace, quotes, word chars, dots, hyphens, underscores, slashes, commas.
    # Any code (parentheses, operators, function names with parens) → not a blocklist.
    if not re.match(r"^[\s'\",\w./_-]*$", segment):
        return False
    return True


# Files that are TextMate/VS Code language grammar definitions — they contain
# command names (ipconfig, nslookup, runas, net localgroup) as syntax-highlighting
# data, not executable code. Matched against the filename.
_GRAMMAR_FILE_RE = re.compile(
    r"(?:^|[-_/])(?:bat|shell|bash|powershell|batch|cmd|sh|fish|zsh)"
    r"(?:[-_](?:syntax|grammar|highlight|language|tmLanguage))?\.js$",
    re.I,
)
# Grammar-definition content markers (TextMate .tmLanguage JSON-in-JS shape):
# high density of `match:`, `begin:`, `end:`, `captures:`, `patterns:` keys.
_GRAMMAR_CONTENT_RE = re.compile(
    r"(?:match|begin|end|captures|patterns|repository|scopeName|fileTypes)\s*:",
)
_GRAMMAR_MIN_KEYS = 4  # at least this many grammar keys → it's a grammar file


def _is_grammar_file(rel: str, text: str) -> bool:
    """Detect a language-grammar definition file (syntax highlighting data, not
    executable code). Two signals: filename matches a language-grammar pattern,
    OR the content has a high density of TextMate grammar keys."""
    if _GRAMMAR_FILE_RE.search(rel):
        # Confirm with content — a grammar file should have grammar keys.
        return len(_GRAMMAR_CONTENT_RE.findall(text[:5000])) >= _GRAMMAR_MIN_KEYS
    # Also catch grammar files by content alone (even without a telling filename).
    return len(_GRAMMAR_CONTENT_RE.findall(text[:5000])) >= _GRAMMAR_MIN_KEYS + 2


def observe_content(inv: Inventory, sigs: Signatures | None = None) -> list[Observation]:
    sigs = sigs or Signatures.load_vendored()
    out: list[Observation] = []
    for f in inv.scannable():
        if f.size > _MAX_BYTES:
            continue
        try:
            text = Path(f.path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        # Skip language-grammar definition files — their command-name examples
        # (ipconfig, nslookup, runas) are syntax-highlighting data, not code.
        if _is_grammar_file(f.rel, text):
            continue
        lang = f.language or "*"
        for hit in sigs.classify_content(text, lang):
            line = text.count("\n", 0, hit.start) + 1 if hit.start is not None else None
            # CRED blocklist filter: a credential filename inside a Set([...]) /
            # exclusion array is a protection pattern, not a credential read.
            if hit.atom.startswith("CRED.") and hit.start is not None:
                if _is_in_blocklist(text, hit.start, hit.start + len(hit.text)):
                    continue
            out.append(Observation(
                atom=hit.atom, confidence=hit.confidence, method="content-regex",
                path=f.rel, line=line, rule_id=hit.rule_id, evidence=hit.text,
            ))
    return out

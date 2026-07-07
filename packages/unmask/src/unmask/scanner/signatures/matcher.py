"""Surface matching.

`match_symbol` reproduces engine `signatures._matches` / `_norm` exactly so
callee and binary-import classification is parity-locked to the reference:

    * normalize: fold ``::`` and ``->`` to ``.``; lowercase unless case_sensitive;
    * base:            the last dotted segment equals a value;
    * exact:           the whole normalized symbol equals a value;
    * suffix:          the symbol ends with a value;
    * exact_or_suffix: equals a value, or ends with ``.`` + value;
    * substring:       a value occurs anywhere;
    * regex:           any value pattern searches (against original-case values).
"""

from __future__ import annotations

import re

from unmask.scanner.signatures.models import ContentRule, MatchRule

# Declarative regex flags used by content signatures (schema `regex_flags`).
REGEX_FLAG_MAP = {"ignore_case": re.IGNORECASE, "multiline": re.MULTILINE, "dotall": re.DOTALL}


def compile_flags(regex_flags: tuple[str, ...]) -> int:
    flags = 0
    for name in regex_flags:
        flags |= REGEX_FLAG_MAP.get(name, 0)
    return flags


def normalize(symbol: str, *, case_sensitive: bool = False) -> str:
    out = symbol.replace("::", ".").replace("->", ".")
    return out if case_sensitive else out.lower()


def match_symbol(candidate: str, rule: MatchRule) -> bool:
    n = normalize(candidate, case_sensitive=rule.case_sensitive)
    values = rule.values if rule.case_sensitive else tuple(v.lower() for v in rule.values)
    base = n.split(".")[-1]
    mode = rule.mode
    if mode == "exact":
        return n in values
    if mode == "base":
        return base in values
    if mode == "suffix":
        return any(n.endswith(v) for v in values)
    if mode == "exact_or_suffix":
        return any(n == v or n.endswith("." + v) for v in values)
    if mode == "substring":
        return any(v in n for v in values)
    if mode == "regex":
        flags = 0 if rule.case_sensitive else re.IGNORECASE
        return any(re.search(v, n, flags) for v in rule.values)
    raise ValueError(f"unsupported match mode {mode!r} in {rule.id}")


def content_matches(text: str, rule: ContentRule):
    """Yield (matched_text, start_offset) for a content rule, honoring cap_per_file."""
    count = 0
    for m in rule.pattern.finditer(text):
        if rule.cap_per_file is not None and count >= rule.cap_per_file:
            return
        count += 1
        yield m.group(0), m.start()

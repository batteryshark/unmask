"""Typed signature-pack models."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class MatchRule:
    """A `callee` or `binary-import` signature: match an extracted symbol string.

    `order` is the signature's index within its pack (gaps where other surfaces
    were interleaved), preserved so classification order matches the reference.
    """
    id: str
    atom: str
    surface: str
    method: str
    languages: tuple[str, ...]
    mode: str
    values: tuple[str, ...]
    case_sensitive: bool
    confidence: float
    summary: str
    priority: int
    order: int

    def applies_to(self, lang: str) -> bool:
        return lang in self.languages or "*" in self.languages


@dataclass(frozen=True)
class ContentRule:
    """A `content` signature: a regex matched against file text."""
    id: str
    atom: str
    surface: str
    method: str
    languages: tuple[str, ...]
    regex: str
    regex_flags: tuple[str, ...]
    confidence: float
    summary: str
    priority: int
    order: int
    cap_per_file: int | None
    mechanic: bool
    pattern: re.Pattern

    def applies_to(self, lang: str) -> bool:
        return lang in self.languages or "*" in self.languages


@dataclass(frozen=True)
class Hit:
    """A classification result. `text`/`start` are set for content matches."""
    atom: str
    confidence: float
    summary: str
    rule_id: str
    text: str | None = None
    start: int | None = None

    def as_tuple(self) -> tuple[str, float, str]:
        """(atom, confidence, summary) — the reference `classify_callee` shape."""
        return (self.atom, self.confidence, self.summary)


@dataclass(frozen=True)
class SignaturePack:
    id: str
    version: str
    source: str
    match_rules: tuple[MatchRule, ...]
    content_rules: tuple[ContentRule, ...]

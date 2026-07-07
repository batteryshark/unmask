"""Callee extraction → call-site atoms.

One interface, two backends:

    extract_calls(src, lang) -> [(callee, line), ...]

* AST (default): tree-sitter via `tree-sitter-language-pack`. Tuned call-node kind
  for js/ts/python (precision), a generic call-kind set for every other grammar.
  Receiver-qualified callees ("Net::HTTP.get", "runtime.exec") survive for matching.
* Regex (fallback): a generic call pattern, used only where the grammar wheel
  isn't importable or the language has no grammar. Lower fidelity by design.

Extracted callees are classified by the slice-1 `classify_callee` (pack-driven),
so meaning stays in the taxonomy.
"""

from __future__ import annotations

import re

from unmask.scanner.observe.atoms import Observation
from unmask.scanner.observe.inventory import Inventory
from unmask.scanner.signatures import Signatures

# canonical language -> tree-sitter grammar name (identity unless listed)
_GRAMMAR = {"shell": "bash"}

# languages we have a grammar for; others use the regex fallback / content only.
_AST_LANGS = {
    "javascript", "typescript", "tsx", "python", "go", "rust", "java", "c",
    "cpp", "objc", "csharp", "kotlin", "scala", "groovy", "ruby", "php",
    "perl", "lua", "r", "swift", "haskell", "elixir", "vb", "shell",
    "powershell", "sql", "hcl", "dockerfile", "html",
}
# Tuned languages keep a narrow call-node kind (precision preserved).
_TUNED_CALL_NODE = {"javascript": "call_expression", "typescript": "call_expression",
                    "tsx": "call_expression", "python": "call"}
_GENERIC_CALL_KINDS = {
    "call_expression", "call", "method_invocation", "invocation_expression",
    "function_call_expression", "member_call_expression", "scoped_call_expression",
    "function_call", "macro_invocation", "message_expression", "command",
    "command_name", "method_call", "object_creation_expression", "new_expression",
    "command_invocation",
}

_TS_TRIED = False
_TS_OK = False
_PARSERS: dict[str, object] = {}


def ts_available() -> bool:
    global _TS_TRIED, _TS_OK
    if not _TS_TRIED:
        _TS_TRIED = True
        try:
            import tree_sitter_language_pack  # noqa: F401
            _TS_OK = True
        except Exception:
            _TS_OK = False
    return _TS_OK


def extraction_mode() -> str:
    return "tree-sitter" if ts_available() else "regex-fallback"


def _parser(grammar: str):
    if grammar not in _PARSERS:
        from tree_sitter_language_pack import get_parser
        _PARSERS[grammar] = get_parser(grammar)
    return _PARSERS[grammar]


# --- binding-agnostic node accessors (tree-sitter 0.23 / language-pack 1.x) ---

def _v(obj, attr):
    x = getattr(obj, attr)
    return x() if callable(x) else x


def _node_kind(n):
    return _v(n, "type") if hasattr(n, "type") else _v(n, "kind")


def _node_children(n):
    if hasattr(n, "children"):
        ch = _v(n, "children")
        if ch is not None:
            return list(ch)
    return [n.child(i) for i in range(_v(n, "child_count"))]


def _node_line(n):
    sp = _v(n, "start_point") if hasattr(n, "start_point") else _v(n, "start_position")
    if isinstance(sp, (tuple, list)):
        return sp[0] + 1
    return getattr(sp, "row", 0) + 1


def _node_text(n, data: bytes) -> str:
    if hasattr(n, "text"):
        return _v(n, "text").decode("utf-8", "replace")
    return data[_v(n, "start_byte"):_v(n, "end_byte")].decode("utf-8", "replace")


def _field(node, *names):
    for fld in names:
        try:
            c = node.child_by_field_name(fld)
        except Exception:
            c = None
        if c is not None:
            return c
    return None


def _callee_text(node, data: bytes) -> str:
    name_node = _field(node, "function", "name", "callee", "method",
                       "function_name", "command_name", "constructor")
    if name_node is None:
        raw = _node_text(node, data).strip()
        raw = raw.split("(", 1)[0].split("{", 1)[0].split("!", 1)[0]
        return raw.splitlines()[0].strip() if raw else ""
    name = _node_text(name_node, data).strip()
    recv = _field(node, "object", "receiver", "scope")
    if recv is not None:
        rt = _node_text(recv, data).strip().splitlines()[0]
        if rt and len(rt) < 80 and "." not in name and "::" not in name:
            return rt + "." + name
    return name


def extract_calls_ast(src: str, lang: str) -> list[tuple[str, int]] | None:
    if not ts_available() or lang not in _AST_LANGS:
        return None
    grammar = _GRAMMAR.get(lang, lang)
    tuned = lang in _TUNED_CALL_NODE
    want = {_TUNED_CALL_NODE[lang]} if tuned else _GENERIC_CALL_KINDS
    try:
        parser = _parser(grammar)
        try:
            tree = parser.parse(src)
        except TypeError:
            tree = parser.parse(src.encode("utf-8"))
        data = src.encode("utf-8")
        out: list[tuple[str, int]] = []
        seen: set[tuple[str, int]] = set()
        stack = [_v(tree, "root_node")]
        while stack:
            node = stack.pop()
            if _node_kind(node) in want:
                if tuned:
                    c = node.child_by_field_name("function")
                    callee = _node_text(c, data).strip() if c is not None else ""
                    line = _node_line(c) if c is not None else _node_line(node)
                else:
                    callee = _callee_text(node, data)
                    line = _node_line(node)
                if callee and (callee, line) not in seen:
                    seen.add((callee, line))
                    out.append((callee, line))
            stack.extend(_node_children(node))
        return out
    except Exception:
        return None


_CALL_RE = re.compile(r"([A-Za-z_$][\w$]*(?:\s*[.:]{1,2}\s*[A-Za-z_$][\w$]*)*)\s*\(")


def extract_calls_regex(src: str, lang: str) -> list[tuple[str, int]]:
    """Generic fallback: identifier(.member)* immediately followed by '('."""
    out: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()
    for i, raw in enumerate(src.splitlines(), start=1):
        for m in _CALL_RE.finditer(raw):
            callee = re.sub(r"\s+", "", m.group(1))
            if callee and (callee, i) not in seen:
                seen.add((callee, i))
                out.append((callee, i))
    return out


def extract_calls(src: str, lang: str) -> list[tuple[str, int]]:
    ast = extract_calls_ast(src, lang)
    return ast if ast is not None else extract_calls_regex(src, lang)


def observe_callee(inv: Inventory, sigs: Signatures | None = None) -> list[Observation]:
    from pathlib import Path
    sigs = sigs or Signatures.load_vendored()
    method = f"source-callee-{'ast' if ts_available() else 'regex'}"
    out: list[Observation] = []
    for f in inv.source_files():
        if not f.language:
            continue
        try:
            text = Path(f.path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for callee, line in extract_calls(text, f.language):
            hit = sigs.classify_callee(callee, f.language)
            if hit is None:
                continue
            out.append(Observation(
                atom=hit.atom, confidence=hit.confidence, method=method,
                path=f.rel, line=line, rule_id=hit.rule_id, evidence=callee,
            ))
    return out

"""A tiny, self-contained, XSS-safe syntax highlighter for report evidence.

Runs on ALREADY-HTML-ESCAPED text (the renderer escapes everything first), so it
only ever inserts ``<span class="tok-X">…</span>`` around matched tokens — it can
never introduce an unescaped ``<``. No external dependency (no Pygments); covers
the languages that show up in MCD evidence: JavaScript/TypeScript, Python, Shell,
JSON, YAML, plus a gentle generic fallback (keywords + strings + comments).

The output is NOT a full grammar lexer — it is a token overlay good enough to make
evidence snippets readable in the pretty HTML report. Fidelity is deliberately
traded for zero-dependency, offline, injection-safe operation.
"""

from __future__ import annotations

import html
import re

# html.escape (quote=True, the renderer's default) turns " → &quot; and ' → &#x27;.
# Since the highlighter runs on ALREADY-escaped text, string regexes must match the
# escaped forms, not raw quotes. Backticks are not escaped.
_DQ = r"&quot;"
_SQ = r"&#x27;"

# Token CSS classes → a small theme inlined by render._CSS.
#   tok-c  comment        tok-s  string       tok-k  keyword
#   tok-n  number         tok-f  function name tok-p  punctuation
#   tok-v  variable/const  tok-o operator      tok-a  attribute/key
#   tok-t  type/builtin   tok-y yaml key

_JS_KEYWORDS = {
    "var", "let", "const", "function", "return", "if", "else", "for", "while", "do",
    "switch", "case", "break", "continue", "new", "delete", "typeof", "instanceof",
    "void", "this", "class", "extends", "super", "import", "export", "from", "default",
    "try", "catch", "finally", "throw", "async", "await", "yield", "of", "in", "null",
    "undefined", "true", "false", "require", "module", "exports", "process", "Buffer",
    "console",
}
_PY_KEYWORDS = {
    "def", "class", "return", "if", "elif", "else", "for", "while", "try", "except",
    "finally", "with", "as", "import", "from", "raise", "pass", "break", "continue",
    "lambda", "global", "nonlocal", "yield", "async", "await", "True", "False", "None",
    "and", "or", "not", "in", "is", "del", "assert", "self", "exec", "eval", "compile",
    "open", "print",
}
_SH_KEYWORDS = {
    "if", "then", "else", "elif", "fi", "for", "do", "done", "while", "case", "esac",
    "function", "return", "exit", "export", "local", "echo", "set", "source", "cd",
    "curl", "wget", "sh", "bash", "sudo", "chmod", "chown", "rm", "cp", "mv", "cat",
    "eval", "exec",
}


def _span(cls: str, text: str) -> str:
    return f'<span class="{cls}">{text}</span>'


def _highlight_strings_comments(text: str, *, comment_re: str, string_re: str) -> str:
    """Color comments and strings FIRST (they may contain keyword-like text), then
    protect them from further tokenization by replacing with placeholders. The
    placeholder uses a letter prefix (R{n}) so the number tokenizer's ``\\b\\d+\\b``
    can't corrupt it."""
    placeholders: list[str] = []

    def stash(m: re.Match) -> str:
        placeholders.append(m.group(0))
        return f"\x00R{len(placeholders) - 1}\x00"

    if comment_re:
        text = re.sub(comment_re, stash, text)
    if string_re:
        text = re.sub(string_re, stash, text)
    return text, placeholders


def _restore_and_wrap(text: str, placeholders: list[str], cls: str) -> str:
    def put(m: re.Match) -> str:
        idx = int(m.group(1))
        return _span(cls, placeholders[idx])
    return re.sub(r"\x00R(\d+)\x00", put, text)


def _highlight_js(text: str) -> str:
    text, strs = _highlight_strings_comments(
        text,
        comment_re=r"//[^\n]*|/\*[\s\S]*?\*/",
        string_re=r"`(?:\\.|[^`\\])*`" + r"|" + _SQ + r"(?:\\.|[^&]|&(?!#x27;))*" + _SQ + r"|" + _DQ + r"(?:\\.|[^&]|&(?!quot;))*" + _DQ,
    )
    # Keywords
    text = re.sub(
        r"\b(" + "|".join(re.escape(k) for k in _JS_KEYWORDS) + r")\b",
        lambda m: _span("tok-k", m.group(0)), text)
    # Numbers
    text = re.sub(r"\b(0x[0-9a-fA-F]+|\d+\.?\d*)\b",
                  lambda m: _span("tok-n", m.group(0)), text)
    # Function calls: name(
    text = re.sub(r"\b([a-zA-Z_$][\w$]*)(\s*\()",
                  lambda m: m.group(1) if m.group(1) in _JS_KEYWORDS
                  else _span("tok-f", m.group(1)) + m.group(2), text)
    return _restore_and_wrap(text, strs, "tok-s")


def _highlight_python(text: str) -> str:
    text, placeholders = _highlight_strings_comments(
        text,
        comment_re=r"#[^\n]*",
        string_re=_SQ + r"(?:[^&]|&(?!#x27;))*" + _SQ + r"|" + _DQ + r"(?:[^&]|&(?!quot;))*" + _DQ,
    )
    text = re.sub(
        r"\b(" + "|".join(re.escape(k) for k in _PY_KEYWORDS) + r")\b",
        lambda m: _span("tok-k", m.group(0)), text)
    text = re.sub(r"\b(0x[0-9a-fA-F]+|\d+\.?\d*)\b",
                  lambda m: _span("tok-n", m.group(0)), text)
    text = re.sub(r"\b(def|class)\s+(\w+)",
                  lambda m: _span("tok-k", m.group(1)) + " " + _span("tok-f", m.group(2)), text)
    return _restore_and_wrap(text, placeholders, "tok-s")


def _highlight_shell(text: str) -> str:
    text, placeholders = _highlight_strings_comments(
        text, comment_re=r"#[^\n]*",
        string_re=_SQ + r"[^&]*" + _SQ + r"|" + _DQ + r"[^&]*" + _DQ)
    text = re.sub(
        r"\b(" + "|".join(re.escape(k) for k in _SH_KEYWORDS) + r")\b",
        lambda m: _span("tok-k", m.group(0)), text)
    # Variables: $VAR, ${VAR}
    text = re.sub(r"\$\{?\w+\}?", lambda m: _span("tok-v", m.group(0)), text)
    # Flags: -x, --foo
    text = re.sub(r"(?<![\w-])(--?[\w-]+)", lambda m: _span("tok-a", m.group(0)), text)
    return _restore_and_wrap(text, placeholders, "tok-s")


def _highlight_json(text: str) -> str:
    text, placeholders = _highlight_strings_comments(
        text, comment_re=r"", string_re=_DQ + r"(?:[^&]|&(?!quot;))*" + _DQ)
    # Object keys: &quot;key&quot;:
    text = re.sub(r"(" + _DQ + r"(?:[^&]|&(?!quot;))*" + _DQ + r")(\s*:)", lambda m: _span("tok-a", m.group(1)) + m.group(2), text)
    # Booleans / null / numbers
    text = re.sub(r"\b(true|false|null)\b", lambda m: _span("tok-k", m.group(0)), text)
    text = re.sub(r"\b(-?\d+\.?\d*)\b", lambda m: _span("tok-n", m.group(0)), text)
    return _restore_and_wrap(text, placeholders, "tok-s")


def _highlight_yaml(text: str) -> str:
    text, placeholders = _highlight_strings_comments(
        text, comment_re=r"#[^\n]*",
        string_re=_SQ + r"[^&]*" + _SQ + r"|" + _DQ + r"[^&]*" + _DQ)
    # Keys: ^key: or  key:
    text = re.sub(r"^(\s*-?\s*)([\w.-]+)(:)", lambda m: m.group(1) + _span("tok-y", m.group(2)) + m.group(3),
                  text, flags=re.MULTILINE)
    # Booleans / null / numbers
    text = re.sub(r"\b(true|false|null|yes|no)\b", lambda m: _span("tok-k", m.group(0)), text)
    return _restore_and_wrap(text, placeholders, "tok-s")


def _highlight_generic(text: str) -> str:
    text, placeholders = _highlight_strings_comments(
        text, comment_re=r"#[^\n]*|//[^\n]*",
        string_re=_SQ + r"[^&]*" + _SQ + r"|" + _DQ + r"[^&]*" + _DQ)
    return _restore_and_wrap(text, placeholders, "tok-s")


_HIGHLIGHTERS = {
    "javascript": _highlight_js, "typescript": _highlight_js, "js": _highlight_js, "ts": _highlight_js,
    "python": _highlight_python, "py": _highlight_python,
    "shell": _highlight_shell, "bash": _highlight_shell, "sh": _highlight_shell,
    "json": _highlight_json,
    "yaml": _highlight_yaml, "yml": _highlight_yaml,
}


def highlight(escaped_text: str, language: str | None = None) -> str:
    """Token-highlight already-HTML-escaped ``escaped_text``.

    ``language`` selects the tokenizer (js/ts/python/shell/json/yaml); unknown or
    None falls back to a gentle generic pass (strings + comments). The input MUST
    already be HTML-escaped — this function only inserts ``<span>`` tags, it never
    escapes, so passing raw text would be an XSS hole.
    """
    if not escaped_text:
        return escaped_text
    lang = (language or "").lower()
    fn = _HIGHLIGHTERS.get(lang, _highlight_generic)
    try:
        return fn(escaped_text)
    except Exception:
        # A highlighter bug must never break the report — return the escaped text as-is.
        return escaped_text


__all__ = ["highlight"]

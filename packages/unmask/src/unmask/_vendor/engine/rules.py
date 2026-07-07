"""Stage 2: Observation production.

Rules emit judgment-free ontology observations. Two surfaces:

  * manifest rules: parse package.json (stdlib, high confidence)
  * source rules: detect calls/idents in JS/Python. Prefers a tree-sitter
                      AST when available (high confidence); falls back to regex
                      (lower confidence, recorded in the rule id + summary).

Coverage is honest: every observation carries a ruleId, a method, and a
confidence. A regex-fallback observation says so.
"""

from __future__ import annotations

import json
import re
from typing import Optional

from .inventory import Inventory, FileEntry
from .model import Observation
from .signatures import load_source_callee_pack

# --------------------------------------------------------------------------
# tree-sitter (optional). Manual node walk avoids Query-API churn across
# tree-sitter versions.
# --------------------------------------------------------------------------
_PARSERS: dict = {}
_TS_TRIED = False
_TS_OK = False


def _ts_available() -> bool:
    global _TS_TRIED, _TS_OK
    if not _TS_TRIED:
        _TS_TRIED = True
        try:
            import tree_sitter_language_pack  # noqa: F401
            _TS_OK = True
        except Exception:
            _TS_OK = False
    return _TS_OK


def _parser(lang: str):
    if lang not in _PARSERS:
        from tree_sitter_language_pack import get_parser
        _PARSERS[lang] = get_parser(lang)
    return _PARSERS[lang]


_JS_LIKE = ("javascript", "typescript", "tsx")  # share the JS classification + regexes

# canonical lang -> tree-sitter grammar name (identity unless listed here)
_GRAMMAR = {"shell": "bash"}

# langs we have a tree-sitter grammar for. Others (batch, applescript, make,
# config, json, yaml, ...) fall back to the regex + content rules only.
_AST_LANGS = {
    "javascript", "typescript", "tsx", "python", "go", "rust", "java", "c",
    "cpp", "objc", "csharp", "kotlin", "scala", "groovy", "ruby", "php",
    "perl", "lua", "r", "swift", "haskell", "elixir", "vb", "shell",
    "powershell", "sql", "hcl", "dockerfile", "html",
}

# Source languages that flow through the call + content rules in _from_text.
SOURCE_LANGS = _AST_LANGS | {"batch", "applescript", "make"}

# Tuned languages keep their narrow call-node kind (precision preserved).
_TUNED_CALL_NODE = {"javascript": "call_expression", "typescript": "call_expression",
                    "tsx": "call_expression", "python": "call"}
# Every other grammar: match any of these call-ish node kinds (probed empirically
# across go/rust/java/c#/ruby/php/bash/c/cpp/objc/...).
_GENERIC_CALL_KINDS = {
    "call_expression", "call", "method_invocation", "invocation_expression",
    "function_call_expression", "member_call_expression", "scoped_call_expression",
    "function_call", "macro_invocation", "message_expression", "command",
    "command_name", "method_call", "object_creation_expression", "new_expression",
    "command_invocation",
}
_CALLEE_FIELDS = ("function", "name", "callee", "method", "command_name",
                  "function_name", "constructor")


def _v(obj, attr):
    """Read an attribute that may be a property or a zero-arg method."""
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
    """Best-effort callee string for a call-ish node, across grammars."""
    name_node = _field(node, "function", "name", "callee", "method",
                       "function_name", "command_name", "constructor")
    if name_node is None:
        # No callee field (rust macro_invocation, bash command_name): take the
        # node's own leading token up to the first call/macro punctuation.
        raw = _node_text(node, data).strip()
        raw = raw.split("(", 1)[0].split("{", 1)[0].split("!", 1)[0]
        return raw.splitlines()[0].strip() if raw else ""
    name = _node_text(name_node, data).strip()
    # Java/Ruby/Kotlin give the bare method name; prepend the receiver so
    # "Net::HTTP.get" / "Runtime.getRuntime().exec" survive for matching.
    recv = _field(node, "object", "receiver", "scope")
    if recv is not None:
        rt = _node_text(recv, data).strip().splitlines()[0]
        if rt and len(rt) < 80 and "." not in name and "::" not in name:
            return rt + "." + name
    return name


def extract_calls(src: str, lang: str) -> Optional[list]:
    """Return list of (callee_text, line) for call nodes, or None if no AST.

    Binding-agnostic: works with the standard tree-sitter package
    (Node.type/.children/.start_point, parse(bytes)) and with
    tree-sitter-language-pack 1.x (Node.kind/.child(i)/.start_position Point,
    parse(str)). Tuned langs (js/ts/tsx/python) keep a narrow call-node kind;
    every other grammar matches a generic call-kind set.
    """
    if not _ts_available() or lang not in _AST_LANGS:
        return None
    grammar = _GRAMMAR.get(lang, lang)
    tuned = lang in _TUNED_CALL_NODE
    want = {_TUNED_CALL_NODE[lang]} if tuned else _GENERIC_CALL_KINDS
    try:
        parser = _parser(grammar)
        try:
            tree = parser.parse(src)                   # language-pack 1.x wants str
        except TypeError:
            tree = parser.parse(src.encode("utf-8"))   # standard binding wants bytes
        data = src.encode("utf-8")
        out, seen = [], set()
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


_XOR_TOKENS = {"^", "^="}


def _bitwise_obfuscation(text: str, lang: str) -> list:
    """Lines where a XOR data-transform appears: an augmented `^=` (in-place XOR)
    anywhere, or a bare `^` inside a loop body (the XOR-decode-over-bytes shape).

    This is AST loop analysis, not a regex: a one-off `flags ^ MASK` outside a
    loop does not fire, which is what separates data transformation from ordinary
    flag/bit math. A cheap `^`-absent check skips the parse for the common case."""
    if "^" not in text:                       # no XOR operator anywhere: skip
        return []
    if not _ts_available() or lang not in _AST_LANGS:
        return []
    try:
        parser = _parser(_GRAMMAR.get(lang, lang))
        try:
            tree = parser.parse(text)
        except TypeError:
            tree = parser.parse(text.encode("utf-8"))
        data = text.encode("utf-8")
    except Exception:
        return []
    hits, seen = [], set()
    stack = [(_v(tree, "root_node"), False)]
    while stack:
        node, in_loop = stack.pop()
        children = _node_children(node)
        if not children:                      # operator tokens are leaves
            txt = _node_text(node, data)
            if txt in _XOR_TOKENS and (txt == "^=" or in_loop):
                line = _node_line(node)
                if line not in seen:
                    seen.add(line)
                    hits.append(line)
                    if len(hits) >= 10:
                        break
            continue
        kind = _node_kind(node)
        loop = in_loop or ("for" in kind or "while" in kind
                           or kind in ("do_statement", "repeat_statement"))
        for c in children:
            stack.append((c, loop))
    return hits


# --------------------------------------------------------------------------
# callee -> atom classification (shared by AST and regex paths)
# --------------------------------------------------------------------------
def _ends(c: str, *suf) -> bool:
    return any(c == s or c.endswith("." + s) for s in suf)


# --------------------------------------------------------------------------
# Multi-language callee tables (Go, Rust, JVM, .NET, Ruby, PHP, C/C++, shell,
# PowerShell, ...). Map per-language calls into the ontology. Each rule is
# (mode, needles, atom, confidence, summary):
#   "base"  -> the call's last segment (case-insensitive) is in needles
#   "exact" -> the full normalized callee (case-insensitive) is in needles
#   "sub"   -> any needle (lowercased) is a substring of the full callee
# Per-language rules are tried first, then the universal table. First hit wins.
# --------------------------------------------------------------------------
_UNIVERSAL_RULES = [
    ("base", {"system", "popen", "_popen", "_wpopen", "shell_exec", "passthru",
              "shellexecute", "shellexecutea", "shellexecutew", "winexec"},
     "EXEC.SHELL", 0.78, "shell command execution"),
    ("base", {"exec", "execv", "execve", "execl", "execle", "execlp", "execvp",
              "execvpe", "fork", "vfork", "posix_spawn", "posix_spawnp",
              "createprocess", "createprocessa", "createprocessw", "processbuilder",
              "proc_open"},
     "EXEC.PROC", 0.78, "process execution"),
    ("sub", {"process.start", "start-process", "runtime.exec", "os/exec",
             "exec.command", "exec.commandcontext"},
     "EXEC.PROC", 0.78, "process execution"),
    ("base", {"eval", "function"}, "LOAD.EVAL", 0.78, "dynamic code evaluation"),
    ("sub", {"invoke-expression"}, "LOAD.EVAL", 0.8, "dynamic code evaluation"),
    ("base", {"dlopen", "dlsym", "loadlibrary", "loadlibrarya", "loadlibraryw",
              "loadlibraryex", "getprocaddress"},
     "LOAD.IMPORT", 0.75, "dynamic native library load"),
    ("sub", {"class.forname", "assembly.load", "activator.createinstance", "libloading"},
     "LOAD.IMPORT", 0.72, "dynamic code / assembly load"),
    ("base", {"unserialize", "readobject", "binaryformatter"},
     "LOAD.DESER", 0.78, "unsafe deserialization"),
    ("sub", {"marshal.load", "pickle.load", "objectinputstream", "yaml.load"},
     "LOAD.DESER", 0.75, "unsafe deserialization"),
    ("sub", {"urlopen", "httpclient", "webclient", "webrequest", "invoke-webrequest",
             "invoke-restmethod", "httpurlconnection", "urlconnection", "reqwest",
             "net.http", "curl_exec", "okhttp", "downloadstring", "downloadfile"},
     "NETW.HTTP", 0.75, "outbound HTTP request"),
    ("base", {"curl", "wget"}, "NETW.HTTP", 0.7, "outbound HTTP request"),
    ("base", {"socket", "getaddrinfo", "gethostbyname", "nc", "ncat"},
     "NETW.SOCKET", 0.6, "raw network socket"),
    ("sub", {"net.dial", "dialcontext"}, "NETW.SOCKET", 0.7, "raw network socket"),
    ("base", {"writealltext", "writeallbytes", "fwrite", "ofstream", "file_put_contents"},
     "FSYS.WRITE", 0.7, "filesystem write"),
    ("sub", {"ioutil.writefile", "os.writefile", "std.fs.write", "fs.write", "os.create"},
     "FSYS.WRITE", 0.72, "filesystem write"),
    ("base", {"fopen", "fread", "ifstream", "readalltext", "readallbytes",
              "file_get_contents", "readfile", "slurp"},
     "FSYS.READ", 0.58, "filesystem read"),
    ("sub", {"ioutil.readfile", "os.readfile", "std.fs.read", "fs.read"},
     "FSYS.READ", 0.66, "filesystem read"),
    ("base", {"rm", "unlink", "remove", "rmdir"}, "FSYS.DELETE", 0.55, "filesystem delete"),
    ("sub", {"base64_decode", "base64_encode", "frombase64string", "tobase64string",
             "b64decode", "b64encode"},
     "XFRM.ENCODE", 0.6, "base64 encode/decode"),
    ("base", {"decrypt"}, "XFRM.ENCRYPT", 0.58, "decryption"),
]

_LANG_RULES = {
    "go": [
        ("sub", {"exec.command", "exec.commandcontext"}, "EXEC.PROC", 0.82, "child process via os/exec"),
        ("sub", {"http.get", "http.post", "http.newrequest", "http.client", "http.do"},
         "NETW.HTTP", 0.8, "outbound HTTP request (net/http)"),
        ("sub", {"net.dial"}, "NETW.SOCKET", 0.72, "raw network socket (net.Dial)"),
        ("sub", {"plugin.open"}, "LOAD.IMPORT", 0.72, "dynamic plugin load"),
    ],
    "rust": [
        ("sub", {"process.command", "command.new"}, "EXEC.PROC", 0.8, "child process (std::process::Command)"),
        ("sub", {"reqwest", "hyper.client", "ureq", "isahc"}, "NETW.HTTP", 0.78, "outbound HTTP request"),
        ("sub", {"libloading", "library.new"}, "LOAD.IMPORT", 0.72, "dynamic library load"),
    ],
    "java": [
        ("base", {"exec"}, "EXEC.PROC", 0.72, "process execution (Runtime.exec)"),
        ("base", {"processbuilder"}, "EXEC.PROC", 0.75, "process execution (ProcessBuilder)"),
        ("base", {"forname"}, "LOAD.IMPORT", 0.7, "reflective class load (Class.forName)"),
        ("base", {"loadlibrary", "load"}, "LOAD.IMPORT", 0.62, "native/library load"),
        ("base", {"readobject"}, "LOAD.DESER", 0.75, "Java deserialization (readObject)"),
        ("sub", {"httpurlconnection", "openconnection", "httpclient"}, "NETW.HTTP", 0.72, "outbound HTTP request"),
    ],
    "csharp": [
        ("sub", {"process.start"}, "EXEC.PROC", 0.78, "process execution (Process.Start)"),
        ("sub", {"assembly.load", "activator.createinstance"}, "LOAD.IMPORT", 0.72, "dynamic assembly load"),
        ("sub", {"httpclient", "webclient", "webrequest"}, "NETW.HTTP", 0.72, "outbound HTTP request"),
        ("sub", {"file.readall", "file.openread"}, "FSYS.READ", 0.66, "filesystem read"),
        ("sub", {"file.writeall", "file.appendall"}, "FSYS.WRITE", 0.7, "filesystem write"),
    ],
    "ruby": [
        ("base", {"system", "spawn"}, "EXEC.PROC", 0.78, "child process execution"),
        ("base", {"exec"}, "EXEC.PROC", 0.75, "process execution"),
        ("base", {"eval", "instance_eval", "class_eval", "module_eval"}, "LOAD.EVAL", 0.78, "dynamic code evaluation"),
        ("sub", {"net.http", "open-uri", "httparty", "faraday", "rest-client"}, "NETW.HTTP", 0.72, "outbound HTTP request"),
        ("sub", {"marshal.load"}, "LOAD.DESER", 0.75, "Ruby Marshal deserialization"),
    ],
    "php": [
        ("base", {"system", "shell_exec", "passthru", "proc_open"}, "EXEC.SHELL", 0.8, "shell command execution"),
        ("base", {"exec", "popen"}, "EXEC.PROC", 0.78, "process execution"),
        ("base", {"eval", "assert", "create_function"}, "LOAD.EVAL", 0.78, "dynamic code evaluation"),
        ("base", {"unserialize"}, "LOAD.DESER", 0.78, "PHP object deserialization"),
        ("base", {"curl_exec"}, "NETW.HTTP", 0.75, "outbound HTTP request (cURL)"),
        ("base", {"file_get_contents"}, "FSYS.READ", 0.55, "file read / URL fetch"),
        ("base", {"file_put_contents", "fwrite"}, "FSYS.WRITE", 0.7, "filesystem write"),
        ("base", {"base64_decode", "base64_encode"}, "XFRM.ENCODE", 0.6, "base64 encode/decode"),
    ],
    "shell": [
        ("base", {"curl", "wget"}, "NETW.HTTP", 0.75, "outbound download (curl/wget)"),
        ("base", {"nc", "ncat", "netcat", "telnet"}, "NETW.SOCKET", 0.65, "raw network connection"),
        ("base", {"eval", "source"}, "LOAD.EVAL", 0.72, "dynamic shell evaluation"),
        ("base", {"python", "python3", "node", "perl", "ruby", "php", "osascript"},
         "EXEC.PROC", 0.6, "spawns an interpreter"),
        ("base", {"rm", "shred"}, "FSYS.DELETE", 0.55, "filesystem delete"),
        ("base", {"base64", "openssl", "gpg", "xxd"}, "XFRM.ENCODE", 0.55, "encode/encrypt utility"),
    ],
    "powershell": [
        ("sub", {"invoke-expression", "iex"}, "LOAD.EVAL", 0.8, "dynamic code evaluation (Invoke-Expression)"),
        ("sub", {"invoke-webrequest", "invoke-restmethod", "webclient", "downloadstring",
                 "downloadfile", "start-bitstransfer"},
         "NETW.HTTP", 0.78, "outbound HTTP request"),
        ("sub", {"start-process"}, "EXEC.PROC", 0.75, "process execution (Start-Process)"),
        ("sub", {"get-content"}, "FSYS.READ", 0.6, "filesystem read"),
        ("sub", {"set-content", "out-file", "add-content"}, "FSYS.WRITE", 0.66, "filesystem write"),
        ("sub", {"frombase64string"}, "XFRM.ENCODE", 0.6, "base64 decode"),
    ],
    "lua": [
        ("base", {"execute"}, "EXEC.PROC", 0.72, "process execution (os.execute)"),
        ("sub", {"socket.http", "http.request"}, "NETW.HTTP", 0.7, "outbound HTTP request"),
    ],
    "groovy": [
        ("base", {"execute"}, "EXEC.PROC", 0.7, "process execution (.execute())"),
    ],
    "vb": [
        ("base", {"shell"}, "EXEC.SHELL", 0.75, "shell command execution (Shell)"),
        ("sub", {"wscript.shell", "createobject"}, "EXEC.SHELL", 0.6, "shell via WScript.Shell"),
    ],
    "elixir": [
        ("sub", {"system.cmd", "os.cmd", ":os.cmd"}, "EXEC.PROC", 0.78, "process execution"),
        ("sub", {"httpoison", "httpc.request", "finch", "tesla"}, "NETW.HTTP", 0.7, "outbound HTTP request"),
    ],
    "haskell": [
        ("base", {"callcommand", "callprocess", "createprocess", "spawncommand",
                  "readprocess", "readcreateprocess", "runcommand"},
         "EXEC.PROC", 0.75, "process execution (System.Process)"),
    ],
    "r": [
        ("base", {"system", "system2"}, "EXEC.PROC", 0.72, "process execution"),
        ("base", {"url"}, "NETW.HTTP", 0.65, "outbound network fetch"),
        # "download.file" needs exact match: base mode compares only the last
        # "."-segment, so it would reduce to "file" and never fire.
        ("exact", {"download.file"}, "NETW.HTTP", 0.65, "outbound network fetch"),
    ],
    "swift": [
        ("base", {"process"}, "EXEC.PROC", 0.6, "process execution (Process/NSTask)"),
    ],
    "kotlin": [
        ("base", {"exec"}, "EXEC.PROC", 0.72, "process execution (Runtime.exec)"),
        ("base", {"processbuilder"}, "EXEC.PROC", 0.72, "process execution (ProcessBuilder)"),
    ],
}


# Import-context gates: an ambiguous callee's atom needs corroborating
# module/import evidence in the same file, else the observation is dropped
# (clearly a different module) or down-weighted (possibly ambiguous). Generalizes
# the original JS child_process gate into one reusable table.
#   (lang, atom, needs, action) where action is "drop" or "downweight".
_IMPORT_GATES = [
    ("javascript", "EXEC.SHELL", ("child_process",), "drop"),   # not RegExp.exec / local helper
    ("typescript", "EXEC.SHELL", ("child_process",), "drop"),
    ("tsx", "EXEC.SHELL", ("child_process",), "drop"),
    ("go", "EXEC.PROC", ("os/exec",), "downweight"),
    ("rust", "EXEC.PROC", ("std::process",), "downweight"),
    ("java", "LOAD.IMPORT", ("ClassLoader", "loadLibrary", "System.load",
                             "forName", "reflect"), "downweight"),  # not img.load()
    ("kotlin", "LOAD.IMPORT", ("ClassLoader", "loadLibrary", "System.load",
                               "forName", "reflect"), "downweight"),
]

_SOURCE_CALLEE_PACK = load_source_callee_pack()
if _SOURCE_CALLEE_PACK is not None:
    _IMPORT_GATES = _SOURCE_CALLEE_PACK.legacy_import_gates()


def signature_pack_status() -> dict:
    if _SOURCE_CALLEE_PACK is None:
        return {
            "loaded": False,
            "reason": "no taxonomy source-callee pack found; using legacy rule tables",
        }
    return {
        "loaded": True,
        "id": _SOURCE_CALLEE_PACK.id,
        "version": _SOURCE_CALLEE_PACK.version,
        "path": str(_SOURCE_CALLEE_PACK.path),
        "calleeSignatures": len(_SOURCE_CALLEE_PACK.rules),
        "observationGates": len(_SOURCE_CALLEE_PACK.observation_gates),
    }


def _apply_import_gates(obs: list, text: str, lang: str) -> list:
    """Drop or down-weight call-derived observations whose atom is ambiguous for
    this language unless the file shows the corroborating import/module."""
    if not any(g[0] == lang for g in _IMPORT_GATES):
        return obs
    out = []
    for o in obs:
        drop = False
        for glang, gatom, needs, action in _IMPORT_GATES:
            if glang == lang and o.atom == gatom and not any(n in text for n in needs):
                if action == "drop":
                    drop = True
                else:
                    o.confidence = round(o.confidence * 0.5, 2)
                    o.summary += " (no import evidence; down-weighted)"
                break
        if not drop:
            out.append(o)
    return out


def _match_rules(callee: str, rules):
    n = callee.replace("::", ".").replace("->", ".")
    base = n.split(".")[-1].lower()
    lc = n.lower()
    for mode, needles, atom, conf, summ in rules:
        if mode == "base" and base in needles:
            return (atom, conf, summ)
        if mode == "exact" and lc in needles:
            return (atom, conf, summ)
        if mode == "sub" and any(x in lc for x in needles):
            return (atom, conf, summ)
    return None


def _classify_other(callee: str, lang: str):
    """Callee -> atom for every non-(js/python) language."""
    if _SOURCE_CALLEE_PACK is not None:
        return _SOURCE_CALLEE_PACK.classify_callee(callee, lang)
    table = _LANG_RULES.get(lang)
    if table:
        hit = _match_rules(callee, table)
        if hit:
            return hit
    return _match_rules(callee, _UNIVERSAL_RULES)


def classify_callee(callee: str, lang: str):
    """Return (atom, base_confidence, summary) or None."""
    c = callee
    if lang in _JS_LIKE:
        if (c == "exec" or _ends(c, "execSync")
                or c.endswith("child_process.exec") or c.endswith("childProcess.exec") or c.endswith("cp.exec")):
            return ("EXEC.SHELL", 0.85, "shell command execution")  # NOT regexp.exec()
        if _ends(c, "spawn", "spawnSync", "execFile", "execFileSync", "fork"):
            return ("EXEC.PROC", 0.85, "child process execution")
        if ("puppeteer" in c or "playwright" in c or "selenium" in c
                or "webdriver" in c or "chromedriver" in c
                or (_ends(c, "launch", "connect") and ("chromium" in c or "browser" in c or "firefox" in c))):
            return ("EXEC.BROWSER", 0.8, "browser automation (drives a real browser)")
        if c == "eval" or _ends(c, "eval") or c == "Function":
            return ("LOAD.EVAL", 0.85, "dynamic code evaluation")
        if c == "import":
            return ("LOAD.IMPORT", 0.7, "dynamic import()")
        if c == "fetch" or "axios" in c or _ends(c, "request", "get", "post") and (
            "http" in c or "axios" in c or "got" in c
        ):
            return ("NETW.HTTP", 0.8, "outbound HTTP request")
        if _ends(c, "writeFile", "writeFileSync", "createWriteStream", "appendFile", "appendFileSync"):
            return ("FSYS.WRITE", 0.8, "filesystem write")
        if _ends(c, "readFile", "readFileSync"):
            return ("FSYS.READ", 0.75, "filesystem read")
        if _ends(c, "readdir", "readdirSync"):
            return ("FSYS.ENUM", 0.75, "directory enumeration")
        if c == "atob" or c == "btoa" or _ends(c, "Buffer.from") or c == "Buffer.from":
            return ("XFRM.ENCODE", 0.6, "base64/buffer decode")
    elif lang == "python":
        if _ends(c, "get_credentials", "get_frozen_credentials"):
            return ("CRED.CLOUD", 0.7, "cloud credential access (SDK)")
        if c == "os.system" or _ends(c, "system", "popen") or c == "pty.spawn":
            return ("EXEC.SHELL", 0.85, "shell command execution")
        if c.startswith("subprocess.") or _ends(c, "Popen", "check_output", "check_call") or (
            c in ("subprocess.run", "subprocess.call")
        ):
            return ("EXEC.PROC", 0.85, "child process execution")
        if ("playwright" in c or "pyppeteer" in c or "webdriver" in c or "selenium" in c
                or "chromedriver" in c
                or (_ends(c, "launch") and any(b in c for b in ("chromium", "firefox", "webkit", "browser")))):
            return ("EXEC.BROWSER", 0.8, "browser automation (drives a real browser)")
        if c in ("eval", "exec", "compile") or _ends(c, "eval", "exec"):
            return ("LOAD.EVAL", 0.85, "dynamic code evaluation")
        if c in ("__import__",) or _ends(c, "import_module"):
            return ("LOAD.IMPORT", 0.8, "dynamic import")
        if _ends(c, "loads", "load") and ("pickle" in c or "marshal" in c or "yaml" in c):
            return ("LOAD.DESER", 0.8, "unsafe deserialization")
        if "requests" in c or _ends(c, "urlopen") or "httpx" in c or "aiohttp" in c:
            return ("NETW.HTTP", 0.8, "outbound HTTP request")
        if "boto3" in c or "botocore" in c or "google.cloud" in c or c.startswith("azure.") or "aws_sdk" in c:
            return ("NETW.HTTP", 0.7, "cloud SDK client (network reach)")
        if _ends(c, "write_text", "write_bytes"):
            return ("FSYS.WRITE", 0.8, "filesystem write")
        if _ends(c, "read_text", "read_bytes"):
            return ("FSYS.READ", 0.75, "filesystem read")
        if _ends(c, "decrypt") or "Fernet" in c:
            return ("XFRM.ENCRYPT", 0.6, "decryption (e.g. Fernet)")
        if "base64" in c and _ends(c, "b64decode", "b64encode", "b85decode", "b16decode"):
            return ("XFRM.ENCODE", 0.6, "base64 decode")
    if lang not in _JS_LIKE and lang != "python":
        return _classify_other(c, lang)
    return None


# --------------------------------------------------------------------------
# regex fallback (when no AST). Capture a callee-ish token before "(".
# --------------------------------------------------------------------------
_CALL_RE = re.compile(r"([A-Za-z_$][\w$.]*)\s*\(")
_URL_RE = re.compile(r"https?://[^\s\"'`)\]]+")
_ENV_JS_RE = re.compile(r"process\.env\.([A-Za-z_][A-Za-z0-9_]*)")
_ENV_PY_RE = re.compile(r"os\.environ(?:\.get\(|\[)\s*[\"']([^\"']+)[\"']")
_CRED_HINT = re.compile(r"(TOKEN|KEY|SECRET|PASS|PASSWORD|CRED|AUTH|APIKEY|PRIVATE|SESSION)", re.I)
_URL_CAP_PER_FILE = 10
_B64_STR_RE = re.compile(r"\.decode\(\s*['\"]base64['\"]")  # py2 "blob".decode('base64')
_SETUP_EXEC_RE = re.compile(
    r"\b(exec|eval)\s*\(|os\.system|subprocess|urlopen|urllib|requests\.|\bPopen\b|socket\."
)
_CRED_PATH_RE = re.compile(
    r"\.aws/credentials|\.aws/config|\.ssh/id_[a-z0-9]+|\.config/gcloud|"
    r"application_default_credentials|\.azure[/\\]|\.netrc|\.docker/config\.json|\.kube/config"
)
_MINIFIED_HINTS = (".min.js", ".min.css", ".bundle.js", "-min.js", ".min.mjs")

# Universal content artifacts (language-agnostic): hardcoded indicators and
# communication endpoints. Capped per file.
_IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_CRYPTO_ADDR_RE = re.compile(r"\b(?:bc1[a-z0-9]{20,60}|0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
_PRIVKEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")
_AWS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
# Sensitive system paths -> ARTF.PATH. Recon / theft targets distinct from the
# credential-file paths already mapped to CRED.CLOUD.
_SENSITIVE_PATH_RE = re.compile(
    r"/etc/(?:passwd|shadow|sudoers|hosts)\b|/proc/(?:self|\d+)/|"
    r"/var/run/docker\.sock|~/\.(?:bash|zsh)_history|"
    r"[A-Za-z]:\\Windows\\System32|\\Windows\\System32")
# Cloud instance-metadata endpoints: reading these returns instance credentials,
# the classic SSRF / cred-theft target.
_CLOUD_META_RE = re.compile(
    r"169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com|"
    r"100\.100\.100\.200|/var/run/secrets/kubernetes\.io|computeMetadata/v1")
# Download piped straight into a shell: the canonical remote-code-execution idiom
# in install scripts, Dockerfiles, and CI run steps.
_CURL_PIPE_SH_RE = re.compile(
    r"\b(?:curl|wget)\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:sh|bash|zsh|ash|python3?|node|perl|ruby)\b")
# Legacy gap-closers, all specific enough to be FP-safe:
# Windows registry access (recon / persistence) -> SYSI.REGISTRY.
_REGISTRY_RE = re.compile(
    r"HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)\b|"
    r"\bHK(?:LM|CU|CR)\\|\b(?:RegOpenKeyEx|RegSetValueEx|RegCreateKeyEx|RegQueryValueEx|RegDeleteKey)\b|"
    r"\bwinreg\.")
# Kernel module load/unload (driver / rootkit) -> LOAD.KERNEL_MODULE.
_KMOD_RE = re.compile(r"\b(?:insmod|modprobe|rmmod|kextload|kextunload|init_module|finit_module)\b")
# Native process-injection APIs -> EXEC.INJECT (the classic injection chain).
_PROC_INJECT_RE = re.compile(
    r"\b(?:VirtualAllocEx|VirtualAlloc|WriteProcessMemory|CreateRemoteThread|NtMapViewOfSection|"
    r"QueueUserAPC|SetWindowsHookEx|process_vm_writev|mach_vm_write|task_for_pid)\b|\bptrace\s*\(")
# Persistence (PRST.*): path/command/marker content rules, language-agnostic
# (run over source and binary strings). Specific enough to be FP-safe. The atom is
# the mechanical fact; the capability lens reads PRST.* as CAP-PERSIST and owns the
# judgment. SERVICE = OS-supervised daemon; STARTUP = boot/login autostart;
# SCHED = time-triggered task; HOOK = loader/PATH/import interception; BOOTKIT =
# pre-OS; EXTENSION = browser/IDE add-on.
_PRST_SERVICE_RE = re.compile(
    r"/etc/systemd/system/|/Library/LaunchDaemons/|\.config/systemd/user/|"
    r"\bsystemctl\s+(?:--user\s+)?enable\b|\bsc(?:\.exe)?\s+create\b|\bNew-Service\b|"
    r"\b(?:CreateService|OpenSCManager)\b|\blaunchctl\s+(?:load|bootstrap)\b|\bKeepAlive\b")
_PRST_STARTUP_RE = re.compile(
    r"\\CurrentVersion\\Run(?:Once)?\b|/\.config/autostart/|/Library/LaunchAgents/|"
    r"\bRunAtLoad\b|@reboot\b|/etc/rc\.local\b|\\Start Menu\\Programs\\Startup|"
    r">>\s*~?/?(?:\.bashrc|\.zshrc|\.bash_profile|\.profile|\.bash_login|\.zprofile)\b")
_PRST_SCHED_RE = re.compile(
    r"\bcrontab\b|/etc/cron[\./]|/var/spool/cron\b|\bschtasks(?:\.exe)?\b|"
    r"\b(?:Register|New)-ScheduledTask\b|\bStartCalendarInterval\b|\bStartInterval\b")
_PRST_HOOK_RE = re.compile(
    r"\bLD_PRELOAD\b|/etc/ld\.so\.preload\b|\bDYLD_INSERT_LIBRARIES\b|\bsitecustomize\b|"
    r"\.git-templates?/|\bcore\.hooksPath\b|\binit\.templatedir\b")
_PRST_BOOTKIT_RE = re.compile(
    r"\bbcdedit\b|/boot/grub/|/boot/efi\b|EFI System Partition|"
    r"\\\\\.\\PhysicalDrive\d|\bSetFirmwareEnvironmentVariable\b")
_PRST_EXTENSION_RE = re.compile(
    r"--(?:install|load|pack)-extension\b|\.crx\b|\.vsix\b|/User Data/[^\n\"']{0,40}/Extensions/")
# Privilege escalation (PRIV.*): elevation utilities, SUID/SGID bit changes,
# Linux capabilities, access-token manipulation, kernel-memory access, and account
# changes. Content rules (source + binary strings); feed the CAP-PRIV surface. Kernel
# MODULE loading stays LOAD.KERNEL_MODULE; PRIV.EXPLOIT is the kernel-memory surface.
_PRIV_SUDO_RE = re.compile(r"\bsudo\s|\bpkexec\b|\bdoas\b|\brunas\b|/etc/sudoers\b")
_PRIV_SUID_RE = re.compile(
    r"\bchmod\s+[ugoa]*[+=][^\s]*s\b|\bchmod\s+[0-7]?[24][0-7]{3}\b|"
    r"-perm\s+[-/]?[0-7]*[24]000\b|\bS_IS[UG]ID\b")
_PRIV_CAP_RE = re.compile(
    r"\b(?:setcap|getcap)\b|\bcap(?:set|get)\b|\bPR_CAP_AMBIENT\b|\bCAP_[A-Z]{2,}[A-Z_]*\b")
_PRIV_TOKEN_RE = re.compile(
    r"\b(?:DuplicateTokenEx|ImpersonateLoggedOnUser|CreateProcessWithTokenW|"
    r"AdjustTokenPrivileges|OpenProcessToken|SeDebugPrivilege)\b|\bkrb5cc")
_PRIV_EXPLOIT_RE = re.compile(r"/dev/k?mem\b|/proc/kcore\b|\bSeLoadDriverPrivilege\b")
_PRIV_ACCOUNT_RE = re.compile(
    r"\b(?:useradd|adduser|usermod|groupadd|userdel|deluser)\b|"
    r"\bnet\s+(?:user|localgroup)\b|\bNew-LocalUser\b|"
    r"\b(?:NetUserAdd|NetLocalGroupAddMembers)\b")
# Anti-analysis / evasion (ENVI.*): sandbox/VM and debugger detection,
# security-tool disabling, anti-forensics, log tampering, masquerade, self-integrity,
# environment fingerprinting, and timing-based anti-analysis. Content rules; they feed
# the curiosity lens (evasion is surprising for most stated purposes), not a capability
# surface. Specific high-signal markers; the harder atoms (MASQ/TAMPER/TIMING) are
# wired with narrow markers and widen later.
_ENVI_SANDBOX_RE = re.compile(
    r"/\.dockerenv\b|\bvboxguest\b|\bvmtoolsd\b|\bVBoxService\b|VMware Tools|\bSbieDll\b|"
    r"/sys/class/dmi/id/product_name")
_ENVI_DEBUG_RE = re.compile(
    r"\bIsDebuggerPresent\b|\bCheckRemoteDebuggerPresent\b|\bNtQueryInformationProcess\b|"
    r"\bPTRACE_TRACEME\b")
_ENVI_SECDISABLE_RE = re.compile(
    r"\b(?:Set|Add)-MpPreference\b|DisableRealtimeMonitoring|\bsetenforce\s+0\b|"
    r"\bcsrutil\s+disable\b|\bspctl\s+--master-disable\b|\bufw\s+disable\b|"
    r"netsh\s+advfirewall[^\n]{0,40}\b(?:off|disable)\b|\biptables\s+-F\b")
_ENVI_FORENSIC_RE = re.compile(
    r"\bhistory\s+-c\b|\bunset\s+HISTFILE\b|HISTFILE=/dev/null|\bshred\b|"
    r"\btouch\s+-t\b|\bSetFileTime\b|/\.bash_history\b|\btimestomp\b")
_ENVI_LOG_RE = re.compile(
    r"\bwevtutil\s+cl\b|\bClear-EventLog\b|\bauditctl\b|:>\s*/var/log/|\btruncate\b[^\n]{0,30}/var/log")
_ENVI_MASQ_RE = re.compile(r"\bPR_SET_NAME\b")
_ENVI_TAMPER_RE = re.compile(r"\bMapFileAndCheckSum\b|\bCheckSumMappedFile\b|/proc/self/exe\b")
_ENVI_ENVCHECK_RE = re.compile(
    r"\bGITHUB_ACTIONS\b|\bGITLAB_CI\b|\bJENKINS_URL\b|\bCONTINUOUS_INTEGRATION\b|\bCIRCLECI\b")
_ENVI_TIMING_RE = re.compile(r"\brdtscp?\b")
# Capability-surface expansion: more network channels (NETW.*), credential
# sources (CRED.*), and filesystem-sensitive atoms (FSYS.*). Content rules; they feed
# CAP-NET / CAP-CRED / CAP-FS-READ so posture and combos see a fuller surface.
_NETW_WEBHOOK_RE = re.compile(
    r"discord(?:app)?\.com/api/webhooks/|api\.telegram\.org/bot|hooks\.slack\.com/services/|"
    r"outlook\.office\.com/webhook|webhook\.site/|\.webhook\.office\.com")
_NETW_WS_RE = re.compile(r"\bwss?://|\bWebSocket\b|\bsocket\.io\b|\bwebsockets?\.(?:connect|client)\b")
_NETW_DNS_RE = re.compile(
    r"\bdnspython\b|\bdns\.resolver\b|\bdns\.lookup\b|\bnslookup\b|"
    r"\bdig\s+(?:[-+@][^\s;|&]*|[A-Za-z0-9.-]+\.[A-Za-z]{2,})|"
    r"\bDnsQuery\b|\bres_query\b")
_CRED_SSH_RE = re.compile(
    r"/\.ssh/|\bid_rsa\b|\bid_ed25519\b|\bid_ecdsa\b|\bauthorized_keys\b|\bknown_hosts\b|\bSSH_AUTH_SOCK\b")
_CRED_KEYCHAIN_RE = re.compile(
    r"\bSecItemCopyMatching\b|\bCredRead\b|security\s+find-(?:generic|internet)-password|"
    r"\bSecretService\b|\blibsecret\b|\bkwallet\b|\bkeyring\.(?:get|set)_password\b")
_CRED_BROWSER_RE = re.compile(
    r"\bLogin Data\b|\bcookies\.sqlite\b|\bkey4\.db\b|\blogins\.json\b|\bLocal State\b|"
    r"Google/Chrome/User Data|Application Support/Google/Chrome|Mozilla/Firefox/Profiles")
# CRED.TOKEN: application-specific token / session-credential stores on disk
# (npm, PyPI, GitHub CLI, Docker, git, netrc). Cloud-CLI cred files are CRED.CLOUD
# and browser stores are CRED.BROWSER; these are the non-cloud, non-browser stores.
_CRED_TOKEN_RE = re.compile(
    r"\.npmrc\b|\.pypirc\b|/\.config/gh/|\.git-credentials\b|"
    r"/\.docker/config\.json|(?<![\w.])\.netrc\b")
_FSYS_CLIPBOARD_RE = re.compile(
    r"\bpbpaste\b|\bpbcopy\b|\bxclip\b|\bxsel\b|\bclip\.exe\b|\b(?:Get|Set)-Clipboard\b|"
    r"navigator\.clipboard|\bpyperclip\b|\b(?:Get|Set)ClipboardData\b")
_FSYS_HIDDEN_RE = re.compile(
    r"\battrib\s+\+[sh]|SetFileAttributes[^\n]{0,40}(?:HIDDEN|SYSTEM)|\bsetxattr\b|\bxattr\s+-w\b")
_FSYS_SENSITIVE_RE = re.compile(
    r"/\.ssh/|/\.aws/|/\.azure/|/\.config/gcloud/|/\.gnupg/|\bwallet\.dat\b|\bkeystore\b|"
    r"/\.docker/config\.json|/\.kube/config\b")
# Crypto primitives (CRPT.*): dual-use by nature, so these are observation-level and
# feed the curiosity lens (notable only when the stated purpose implies no crypto).
# Needles favour the call/algorithm forms over bare names to keep false positives low.
_CRPT_SYMENC_RE = re.compile(
    r"\bAES\.new\b|Cipher\.getInstance\(\s*[\"']AES|createCipheriv|CryptoJS\.AES|"
    r"\bAES[/_-](?:CBC|GCM|CTR|ECB|CFB)\b|\bChaCha20\b|\bSalsa20\b|\bBlowfish\b|\b3DES\b|"
    r"\bDESede\b|\bFernet\b|EVP_EncryptInit")
_CRPT_ASYMENC_RE = re.compile(
    r"\bRSA\.generate\b|PKCS1_OAEP|Cipher\.getInstance\(\s*[\"']RSA|publicEncrypt|"
    r"privateDecrypt|\bRSA[/_-](?:ECB|OAEP)|\brsa\.encrypt\b")
_CRPT_HASH_RE = re.compile(
    r"hashlib\.(?:md5|sha\d+|blake2[bs]|sha3_\d+)|createHash\s*\(|MessageDigest\.getInstance|"
    r"CryptoJS\.(?:SHA\d*|MD5)|EVP_DigestInit|\bmd5sum\b|\bsha256sum\b")
_CRPT_SIGN_RE = re.compile(
    r"createHmac|HMAC\.new|hmac\.new|Signature\.getInstance|\bSigningKey\b|\bVerifyingKey\b|"
    r"jwt\.(?:sign|encode|decode)|AWS4-HMAC-SHA256|crypto\.(?:sign|verify)\b")
_CRPT_KEYGEN_RE = re.compile(
    r"generateKeyPair|\bPBKDF2\b|\bHKDF\b|KeyGenerator\.getInstance|crypto\.generateKey|"
    r"\bderive_key\b|EC\.generate\b")
_CRPT_KEYEX_RE = re.compile(
    r"\bDiffieHellman\b|\bECDHE?\b|\bX25519\b|\bcurve25519\b|KeyAgreement\.getInstance|"
    r"crypto\.diffieHellman")
_CRPT_RNG_RE = re.compile(
    r"secrets\.token_|os\.urandom\b|getRandomValues|\bSecureRandom\b|/dev/urandom|"
    r"\bCryptGenRandom\b|SecRandomCopyBytes|\bRAND_bytes\b|BCryptGenRandom")
_CRPT_CERT_RE = re.compile(
    r"_create_unverified_context|ssl\.CERT_NONE|\bverify\s*=\s*False\b|rejectUnauthorized\s*:\s*false|"
    r"InsecureSkipVerify|NODE_TLS_REJECT_UNAUTHORIZED|SecTrustSettingsSetTrustSettings|"
    r"CERT_STORE_ADD|check_hostname\s*=\s*False")
_CRPT_CREDHASH_RE = re.compile(
    r"\bbcrypt\b|\bscrypt\b|\bargon2\b|password_verify|\bhashpw\b|\bcrypt\.crypt\b")
_CRPT_CUSTOM_RE = re.compile(
    r"0x6a09e667|0x67452301|0xefcdab89|0x510e527f|round_constant|\brcon\[|\bs_?box\b")
# System-information recon (SYSI.*): mostly ubiquitous and dual-use, so these are
# low-confidence observations. PROC/PROCMEM are higher-signal (process enumeration,
# reading another process's memory). Recon's real signal is the aggregate profile.
_SYSI_OS_RE = re.compile(
    r"os\.platform\(|sys\.platform|platform\.(?:system|release|machine|version)\(|os\.arch\(|"
    r"\buname -a\b|/etc/os-release|GetVersionEx|RtlGetVersion|\bsw_vers\b")
_SYSI_HW_RE = re.compile(
    r"os\.cpus\(|cpu_count\(|/proc/cpuinfo|/proc/meminfo|\bsysctl\b[^\n]{0,20}hw\.|GetSystemInfo|"
    r"Win32_Processor|os\.totalmem\(|psutil\.(?:cpu_count|virtual_memory)|\bnproc\b|\blscpu\b|\bdmidecode\b")
_SYSI_NET_RE = re.compile(
    r"\bifconfig\b|\bipconfig\b|\bip addr\b|getifaddrs|os\.networkInterfaces|GetAdaptersInfo|"
    r"/proc/net/|\barp -a\b|\bnetstat\b|\broute print\b")
_SYSI_PROC_RE = re.compile(
    r"\bps -ef\b|\bps aux\b|\btasklist\b|psutil\.process_iter|EnumProcesses|CreateToolhelp32Snapshot|\bpgrep\b")
_SYSI_PROCMEM_RE = re.compile(
    r"/proc/\d+/maps|ReadProcessMemory|process_vm_readv|task_for_pid|\bvm_read\b|ptrace\([^\n]{0,20}PEEK")
_SYSI_SW_RE = re.compile(
    r"\bdpkg -l\b|\brpm -qa\b|\bbrew list\b|\bpip (?:list|freeze)\b|\bnpm ls\b|Win32_Product|"
    r"/var/lib/dpkg|reg query[^\n]{0,40}Uninstall")
_SYSI_USER_RE = re.compile(
    r"\bwhoami\b|\bid -un?\b|os\.getlogin|/etc/passwd|getpwuid|GetUserName|\bnet user\b")
# Timing (TIME.*): DELAY/GET/SCHED are common and low-signal; CMP (clock vs a fixed
# date that gates behavior) is the logic-bomb signature and the high-value atom.
_TIME_DELAY_RE = re.compile(
    r"time\.sleep\(\s*\d{2,}|Thread\.sleep\(\s*\d{4,}|\bsleep \d{2,}|\busleep\(|\bnanosleep\b|asyncio\.sleep\(\s*\d{2,}")
_TIME_GET_RE = re.compile(
    r"time\.time\(\)|Date\.now\(\)|datetime\.(?:now|utcnow)\(\)|System\.currentTimeMillis|"
    r"time\.Now\(\)|gettimeofday|clock_gettime")
_TIME_SCHED_RE = re.compile(
    r"setInterval\(|threading\.Timer|\bAPScheduler\b|schedule\.every\(|new Timer\(|\bnode-cron\b")
_TIME_CMP_RE = re.compile(
    r"(?:Date\.now\(\)|time\.time\(\)|datetime\.(?:now|utcnow)\(\))\s*[<>]=?|"
    r"[<>]=?\s*datetime(?:\.datetime)?\(\s*\d{4}|[<>]=?\s*new Date\(\s*[\"']?\d{4}")
# Resource abuse (RSRC.*): marker-based. FORK (fork bombs), CPU/GPU (cryptomining),
# DISK (zero-fill) are high-signal needles. Generic exhaustion (MEM/NET) needs runtime
# or loop analysis and stays a declared partial: only narrow markers fire here.
_RSRC_FORK_RE = re.compile(r":\(\)\s*\{\s*:\s*\|\s*:&\s*\}\s*;\s*:|%0\s*\|\s*%0")
_RSRC_CPU_RE = re.compile(
    r"stratum\+(?:tcp|ssl)://|\bxmrig\b|\bcryptonight\b|\brandomx\b|\bcoinhive\b|\bminexmr\b|"
    r"\bsupportxmr\b|\bnicehash\b|\bnanopool\b|donate-level")
_RSRC_GPU_RE = re.compile(
    r"\bethminer\b|\bnbminer\b|\bt-rex\b|\bgminer\b|\blolMiner\b|\bphoenixminer\b|\bnvidia-smi\b")
_RSRC_DISK_RE = re.compile(
    r"dd\s+if=/dev/(?:zero|urandom)[^\n]{0,40}of=|\bfallocate\s+-l\b|\bmkfile\b|cat /dev/zero\s*>|fsutil file createnew")
_RSRC_MEM_RE = re.compile(r"malloc\(\s*\d{9,}|new\s+byte\[\s*\d{9,}|bytearray\(\s*\d{9,}")
_RSRC_NET_RE = re.compile(r"\bhping3\b|\bslowloris\b|\bab -n \d{5,}|\b(?:LOIC|HOIC)\b")
# Dynamic loading (LOAD.*): native library loading, WASM instantiation, runtime
# code generation, and reflection. All feed CAP-DYNLOAD (lenses maps the LOAD
# prefix). REFLECT is scoped to high-signal forms (no bare getattr) to avoid
# flooding ordinary Python. CODEGEN avoids re.compile by requiring an exec/eval
# mode arg or a code-object constructor.
_LOAD_DYLIB_RE = re.compile(
    r"\bdlopen\s*\(|\bLoadLibrary(?:A|W|ExA|ExW)?\s*\(|ctypes\.(?:CDLL|cdll|WinDLL|windll)\b|"
    r"\bffi\.(?:load|dlopen)\b|System\.load(?:Library)?\s*\(")
_LOAD_WASM_RE = re.compile(
    r"WebAssembly\.(?:instantiate(?:Streaming)?|compile(?:Streaming)?|Module|Instance)|"
    r"\bwasmtime\b|\bwasmer\b|\bwasm3\b|new WebAssembly\b")
_LOAD_CODEGEN_RE = re.compile(
    r"new Function\s*\(|types\.CodeType\s*\(|\bcompile\([^)\n]{0,200}?,\s*['\"](?:exec|eval|single)['\"]|"
    r"\bllvmlite\b|@(?:numba\.)?n?jit\b")
_LOAD_REFLECT_RE = re.compile(
    r"Class\.forName\s*\(|\.getDeclaredMethod\s*\(|\.getMethod\s*\(|Method\.invoke\s*\(|"
    r"\.setAccessible\s*\(\s*true|Reflect\.(?:get|set|construct|apply|defineProperty|ownKeys)\b")
# Remaining network channels (NETW.*). All feed CAP-NET except IPC (local-only).
# LISTEN is scoped to server forms with a port (not Function.bind / event .listen).
_NETW_LISTEN_RE = re.compile(
    r"https?\.createServer|net\.createServer|socketserver\.|\bHTTPServer\s*\(|\bTcpListener\b|"
    r"\bServerSocket\b|net\.Listen\(|\bbind_shell\b|app\.listen\(|\.listen\(\s*\d")
_NETW_EMAIL_RE = re.compile(
    r"\bsmtplib\b|\bimaplib\b|\bSMTP\b|\bsendmail\b|\bnodemailer\b|System\.Net\.Mail|MailMessage|"
    r"\bsendgrid\b|ses\.send_email")
_NETW_GRPC_RE = re.compile(
    r"grpc\.(?:insecure_channel|secure_channel|server|aio|Dial)|ManagedChannelBuilder|GrpcChannel|@grpc/grpc-js")
_NETW_BROKER_RE = re.compile(
    r"KafkaProducer|KafkaConsumer|\bpika\b|\bamqp\b|\bpaho\.mqtt\b|\bmqtt\.connect\b|\bnats\.connect\b|"
    r"aio_pika|\bcelery\b|ServiceBusClient|boto3[^\n]{0,20}sqs")
_NETW_IPC_RE = re.compile(
    r"\bAF_UNIX\b|socket\.AF_UNIX|\bmkfifo\b|CreateNamedPipe|win32pipe|\\\\\.\\pipe\\|"
    r"\bshm_open\b|\bshmget\b|CreateFileMapping|\bMAP_SHARED\b|DBusConnection")
_NETW_SSE_RE = re.compile(
    r"\bEventSource\s*\(|text/event-stream|\bServerSentEvents?\b|sse_starlette|EventSourcePolyfill")
_NETW_DECENTRAL_RE = re.compile(
    r"\bipfs\b|\bbittorrent\b|\bwebrtc\b|RTCPeerConnection|\blibp2p\b|web3\.|\bethers\b|\bsolana\b|"
    r"\.onion\b|\bstun:|\bturn:")
# Obfuscation transforms (XFRM.*), obfuscation has no blast radius, so these feed
# the curiosity lens. UNICODE = bidi overrides + zero-width (the Trojan Source
# vector), excluding U+200D (emoji ZWJ) and U+FEFF (BOM) to avoid false positives.
# bidi overrides (U+202A-202E, U+2066-2069) + zero-width space/non-joiner/word-joiner;
# built from explicit codepoints so the source stays ASCII and is not self-flagged.
_XFRM_INVIS = [0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068,
               0x2069, 0x200b, 0x200c, 0x2060]
_XFRM_UNICODE_RE = re.compile("[" + "".join(chr(c) for c in _XFRM_INVIS) + "]")
_XFRM_STRCON_RE = re.compile(
    r"String\.fromCharCode\(|(?:\\x[0-9a-fA-F]{2}){4,}|(?:chr\(\d+\)\s*\+\s*){3,}")
_XFRM_PACK_RE = re.compile(r"eval\(function\(p,a,c,k,e,|\b_0x[0-9a-fA-F]{4,6}\b")
_XFRM_STEG_RE = re.compile(
    r"\bsteghide\b|\bstegano\b|\boutguess\b|\bzsteg\b|\bstepic\b|least.{0,3}significant.{0,3}bit")
_XFRM_XOR_B64_RE = re.compile(
    r"(?:Buffer\.from\s*\([^)]{0,160}['\"]base64['\"]|atob\s*\([^)]{0,160}\))"
    r"[\s\S]{0,1800}"
    r"(?:String\.fromCharCode\s*\([^)]{0,120}\^|charCodeAt\s*\([^)]*\)\s*\^|"
    r"\b[A-Za-z_$][\w$]*\s*\^\s*[A-Za-z_$][\w$]*)"
    r"[\s\S]{0,900}"
    r"(?:\.split\s*\(\s*['\"],[ '\"]?\s*\)|return\s+[A-Za-z_$][\w$]*\s*;)",
    re.I,
)
_XFRM_CTRLFLOW_RE = re.compile(
    r"(?:while\s*\(\s*(?:true|1|!!\[\])\s*\)|for\s*\(\s*;\s*;\s*\))[\s\S]{0,2000}"
    r"switch\s*\([^)\n]{1,120}\)[\s\S]{0,2000}\b(?:continue|case\s+['\"]?\d+['\"]?)\b|"
    r"['\"](?:\d+\|){3,}\d+['\"]\s*\.split\(\s*['\"]\|['\"]\s*\)[\s\S]{0,1500}switch\s*\(|"
    r"\b(?:controlFlowFlattening|control_flow_flattening|opaquePredicate|opaque_predicate)\b",
    re.I)
_XFRM_RENAME_IDENT_RE = re.compile(r"\b_0x[0-9a-fA-F]{4,}\b")
# Agent-facing prompt marking. This is deliberately narrower than "current date
# in a prompt": require environment/region gating plus Unicode-confusable output
# selection near a prompt/date string.
_AITM_PROMPTMARK_RE = re.compile(
    r"(?:ANTHROPIC_BASE_URL|[A-Z_]*(?:BASE_URL|PROXY|HOST)[A-Z_]*|hostname|timezone|"
    r"Asia/Shanghai|Asia/Urumqi)"
    r"[\s\S]{0,4000}"
    r"(?:\\u2019|\\u02BC|\\u02B9|right single quotation mark|modifier letter apostrophe|"
    r"modifier letter prime)"
    r"[\s\S]{0,4000}"
    r"(?:Today\$\{[^}]{1,120}\}s date is|Today(?:\\u(?:2019|02BC|02B9)|['\"])s date is|"
    r"currentDate|system prompt)",
    re.I,
)
# Supply-chain package operations (PKGM.*) beyond the wired INSTALL/TYPOSQUAT/
# UNDECLARED. BINDOWN (download a binary at install) joins CAP-INSTALL; HOOK is
# build-system injection; PUBLISH and DEPMOD (registry/lockfile redirect) are
# observation-level supply-chain markers.
_PKGM_HOOK_RE = re.compile(
    r"\badd_custom_command\b|\bexecute_process\s*\(|\bgenrule\s*\(|\bcommandLine\s*[\(\[]")
_PKGM_BINDOWN_RE = re.compile(
    r"\bnode-pre-gyp\b|\bprebuild-install\b|https?://[^\s\"'`]+\.(?:so|dll|dylib|node|exe)\b|"
    r"releases/download/[^\s\"'`]+\.(?:so|dll|dylib|node|exe)")
_PKGM_PUBLISH_RE = re.compile(
    r"\bnpm publish\b|\byarn publish\b|\btwine upload\b|\bcargo publish\b|\bgem push\b|\bpoetry publish\b")
_PKGM_DEPMOD_RE = re.compile(
    r"registry\s*=\s*https?://|--registry\s+https?://|\bindex-url\s*=|--index-url\b|"
    r"(?:writeFileSync|writeFile|fs\.write|open)\([^\n]{0,40}(?:package-lock\.json|yarn\.lock|Pipfile\.lock|go\.sum)")
# Remaining filesystem atoms (FSYS.*). PERM (chmod/chown) and LINK (symlinks)
# are mutations -> CAP-FS-WRITE; TEMP and ARCHIVE are common, so observation-level.
_FSYS_PERM_RE = re.compile(
    r"\bchmod\b|os\.chmod|fs\.chmod|\bfchmod\b|\bchown\b|os\.chown|SetFileAttributes|\bicacls\b|SetSecurityInfo")
_FSYS_LINK_RE = re.compile(
    r"os\.symlink|fs\.symlink|os\.link\b|\bln -s\b|CreateSymbolicLink|\bmklink\b")
_FSYS_TEMP_RE = re.compile(
    r"\btempfile\.|\bmkstemp\b|\bmktemp\b|NamedTemporaryFile|os\.tmpdir|GetTempPath|TemporaryDirectory|TemporaryFile")
_FSYS_ARCHIVE_RE = re.compile(
    r"\.extractall\(|zipfile\.ZipFile|tarfile\.open|shutil\.unpack_archive|\bunzip \b|\btar -x|\bpy7zr\b")
# Embedded-artifact extraction (ARTF.*). CREDENTIAL uses provider key formats
# (high confidence, the static-artifact counterpart to the runtime CRED.* atoms)
# and CMD catches embedded command lines. DOMAIN/HASH/TIMESTAMP are capped
# artifact-inventory observations: useful IOCs, low confidence by design.
_ARTF_CREDENTIAL_RE = re.compile(
    r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\bgh[posru]_[A-Za-z0-9]{30,}\b|\bxox[baprs]-[A-Za-z0-9-]{10,}\b|"
    r"\b(?:sk|pk)_live_[A-Za-z0-9]{20,}\b|\bAIza[A-Za-z0-9_-]{35}\b|"
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}\b|-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")
_ARTF_CMD_RE = re.compile(
    r"powershell(?:\.exe)?\s+-[eE]nc(?:odedCommand)?\b|cmd(?:\.exe)?\s+/c\s|/bin/(?:sh|bash)\s+-c\s|\bbash\s+-c\s+['\"]")
_DOMAIN_RE = re.compile(
    r"(?<![\w@:/-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"(?:com|net|org|io|dev|app|co|cloud|info|biz|ru|cn|uk|de|fr|jp|br|au|ca|us|gov|edu|mil|onion)\b",
    re.I)
_DOMAIN_CONTEXT_RE = re.compile(
    r"(?:\b(?:domain|host|hostname|server|endpoint|callback|webhook|c2|dns|ioc|allowlist|blocklist|"
    r"denylist|proxy|connect|exfil|beacon|issuer|subjectaltname|san)\b|"
    r"[A-Za-z_]*(?:domain|host|endpoint|callback|webhook|beacon)[A-Za-z_]*)",
    re.I)
_DOMAIN_CAP = 6
_HASH_RE = re.compile(r"\b(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}|[A-Fa-f0-9]{96}|[A-Fa-f0-9]{128})\b")
_HASH_CONTEXT_RE = re.compile(r"\b(?:md5|sha(?:1|224|256|384|512)?|hash|digest|checksum|fingerprint|integrity)\b", re.I)
_HASH_FILE_CONTEXT_RE = re.compile(r"^\s*[A-Fa-f0-9]{32,128}\s+[\w./-]+\.[A-Za-z0-9]{1,12}\b")
_HASH_CAP = 6
_TIMESTAMP_ISO_RE = re.compile(
    r"\b(?:19|20)\d{2}-[01]\d-[0-3]\d[T ][0-2]\d:[0-5]\d"
    r"(?::[0-5]\d(?:\.\d{1,9})?)?(?:Z|[+-][0-2]\d:?[0-5]\d)\b")
_TIMESTAMP_EPOCH_RE = re.compile(r"\b(?:9[5-9]\d{8}|1\d{9}|2\d{9}|3\d{9}|4[01]\d{8}|1[0-9]{12})\b")
_TIMESTAMP_CONTEXT_RE = re.compile(
    r"\b(?:timestamp|time_?stamp|expires(?:_?at)?|expiry|not_?before|not_?after|created_?at|"
    r"updated_?at|build_?time|compile_?time|compiled|valid_?(?:from|until|to))\b",
    re.I)
_TIMESTAMP_CAP = 6
# In-memory / reflective load chains: decode/decompress/byte-array material
# flowing directly into eval/exec, VM contexts, Assembly.Load, defineClass, or
# memfd/fexecve. Kept narrow so ordinary dynamic imports stay LOAD.IMPORT/EVAL.
_LOAD_MEMCHAIN_RE = re.compile(
    r"(?:"
    r"(?:eval|exec)\s*\([^;\n]{0,160}(?:Buffer\.from|atob|base64\.(?:b64decode|decodebytes)|"
    r"marshal\.loads|zlib\.decompress|gzip\.decompress)|"
    r"new\s+Function\s*\([^;\n]{0,120}(?:Buffer\.from|atob)|"
    r"vm\.(?:runInThisContext|runInNewContext|compileFunction)\s*\(|"
    r"(?:\[System\.Reflection\.Assembly\]|Reflection\.Assembly|Assembly)\s*(?:\.|::)\s*Load\s*\("
    r"\s*(?:\[Convert\]::FromBase64String|Convert\.FromBase64String|File\.ReadAllBytes)|"
    r"defineClass\s*\([^;\n]{0,180}(?:byte\[\]|\bbytes\b|,\s*0\s*,)|"
    r"\bmemfd_create\b[\s\S]{0,500}\bfexecve\b|\bfexecve\s*\()",
    re.I)
# Direct system calls (EXEC.SYSCALL): invoking the kernel below the libc/NTDLL
# wrappers, which bypasses library-level hooks and logging. Feeds CAP-EXEC.
_EXEC_SYSCALL_RE = re.compile(
    r"\bint\s+0x80\b|\bsysenter\b|\bsyscall\.Syscall6?\b|\b__NR_\w+|\bNt(?:CreateThreadEx|"
    r"AllocateVirtualMemory|WriteVirtualMemory|ProtectVirtualMemory|MapViewOfSection)\b|"
    r"\bsyscall\s*\(\s*(?:SYS_|\d)|ctypes[^\n]{0,30}\bntdll\b")

# CI/CD workflow pack. These stay in existing ontology atoms: workflow triggers
# and dependency choices are PKGM.*, token authority is PRIV.TOKEN, and GitHub
# secret contexts are CRED.ENV.
_GHA_PULL_REQUEST_TARGET_RE = re.compile(
    r"(?im)^\s*(?:-\s*)?pull_request_target\s*:?\s*$|^\s*on\s*:[^\n#]*\bpull_request_target\b")
_GHA_WRITE_ALL_RE = re.compile(r"(?im)^\s*permissions\s*:\s*write-all\s*$")
_GHA_WRITE_SCOPE_RE = re.compile(
    r"(?im)^\s*(?:actions|attestations|checks|contents|deployments|discussions|id-token|"
    r"issues|packages|pages|pull-requests|repository-projects|security-events|statuses)\s*:\s*write\s*$")
_GHA_SECRET_RE = re.compile(
    r"\$\{\{\s*(?:secrets\.[A-Za-z_][A-Za-z0-9_]*|toJson\(\s*secrets\s*\))\s*\}\}", re.I)
_GHA_TOKEN_RE = re.compile(r"\$\{\{\s*github\.token\s*\}\}|\bGITHUB_TOKEN\b|\bGH_TOKEN\b", re.I)
_GHA_ARTIFACT_UPLOAD_RE = re.compile(r"(?im)^\s*(?:-\s*)?uses\s*:\s*actions/upload-artifact@", re.I)
_GHA_ARTIFACT_DOWNLOAD_RE = re.compile(r"(?im)^\s*(?:-\s*)?uses\s*:\s*actions/download-artifact@", re.I)
_GHA_UNPINNED_ACTION_RE = re.compile(
    r"(?im)^\s*(?:-\s*)?uses\s*:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@(main|master|HEAD|latest)\s*$")
_GHA_PR_HEAD_RE = re.compile(r"github\.event\.pull_request\.head\.(?:ref|sha|repo\.full_name)", re.I)

# Container pack: Dockerfile plus narrow Docker Compose/Kubernetes security
# context markers. Privilege and secret-copy markers are high value and remain
# mechanical observations; image/layer semantics stay in the coverage gaps.
_DOCKER_USER_ROOT_RE = re.compile(r"(?im)^\s*USER\s+(?:0|root)(?:\s|$)")
_DOCKER_SECRET_COPY_RE = re.compile(
    r"(?im)^\s*(?:ADD|COPY)\s+(?:--[^\n]+\s+)*[^\n]*(?:\.env\b|secret|\.ssh|id_rsa|"
    r"id_ed25519|\.aws|\.kube|\.docker/config\.json)[^\n]*")
_DOCKER_REMOTE_ADD_RE = re.compile(r"(?im)^\s*ADD\s+https?://\S+\s+\S+")
_DOCKER_ENTRY_SHELL_RE = re.compile(
    r"(?im)^\s*(?:ENTRYPOINT|CMD)\s+.*\b(?:sh|bash|ash)\b.*(?:['\"]-c['\"]|\s-c(?:\s|$)|,\s*['\"]-c['\"]).*")
_DOCKER_ENTRY_DOWNLOAD_RE = re.compile(
    r"(?im)^\s*(?:ENTRYPOINT|CMD)\s+.*\b(?:curl|wget)\b[^\n|]{0,200}\|\s*(?:sh|bash|ash)\b")
_CONTAINER_PRIVILEGED_RE = re.compile(r"(?im)^\s*privileged\s*:\s*true\s*$")
_CONTAINER_CAP_RE = re.compile(
    r"(?im)^\s*(?:cap_add|capAdd)\s*:|^\s*add\s*:\s*\[?[^\n\]]*CAP_[A-Z_]+|"
    r"\bSYS_ADMIN\b|\bNET_ADMIN\b|\bSYS_PTRACE\b")
_CONTAINER_ROOT_RE = re.compile(r"(?im)^\s*(?:runAsUser|run_as_user|user)\s*:\s*['\"]?0['\"]?\s*$")
_CONTAINER_ESC_RE = re.compile(r"(?im)^\s*allowPrivilegeEscalation\s*:\s*true\s*$")
_CONTAINER_SECRET_MOUNT_RE = re.compile(
    r"(?im)^\s*(?:-\s*)?(?:secretName|secretRef|secretKeyRef|imagePullSecrets)\s*:")
_FTP_URL_RE = re.compile(r"\bftps?://[^\s\"'`)\]]+")
_SSH_URL_RE = re.compile(r"\b(?:ssh|sftp|git\+ssh)://[^\s\"'`)\]]+")
_ENV_OTHER_RE = re.compile(
    r"(?:getenv|GetEnvironmentVariable|ENV)\s*[\(\[]\s*[\"']([A-Za-z_][A-Za-z0-9_]*)[\"']")
_BENIGN_IPS = {"0.0.0.0", "127.0.0.1", "255.255.255.255", "1.1.1.1", "8.8.8.8", "0.0.0.1"}
_IP_CAP = 8
_SOURCE_STRING_SCAN_MAX = 128_000


def _low_value_file(name: str, text: str) -> bool:
    """Skip minified/bundled/generated/huge files: they flood the report with
    noise and rarely represent first-party behavior."""
    if any(name.endswith(h) for h in _MINIFIED_HINTS):
        return True
    if len(text) > 2_000_000:
        return True
    longest = max((len(line) for line in text.split("\n", 60)[:60]), default=0)
    return longest > 5000  # one very long line ~ minified/bundled/generated


def _line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def _line_bounds(text: str, idx: int) -> tuple[int, int]:
    start = text.rfind("\n", 0, idx) + 1
    end = text.find("\n", idx)
    return start, len(text) if end == -1 else end


def _line_at(text: str, idx: int) -> str:
    start, end = _line_bounds(text, idx)
    return text[start:end]


def _overlaps(span: tuple[int, int], spans: list[tuple[int, int]]) -> bool:
    a, b = span
    return any(a < y and x < b for x, y in spans)


def _context_without_match(text: str, start: int, end: int, pad: int = 80) -> str:
    lo = max(0, start - pad)
    hi = min(len(text), end + pad)
    return text[lo:start] + text[end:hi]


def _hash_context_ok(text: str, start: int, end: int) -> bool:
    line = _line_at(text, start)
    if _HASH_FILE_CONTEXT_RE.search(line):
        return True
    return bool(_HASH_CONTEXT_RE.search(_context_without_match(text, start, end)))


def _timestamp_epoch_value(raw: str) -> Optional[int]:
    try:
        value = int(raw)
    except ValueError:
        return None
    if len(raw) == 13:
        value //= 1000
    # 2000-01-01 through 2100-01-01: broad enough for fixed artifact metadata,
    # narrow enough to avoid arbitrary long numeric ids.
    if 946684800 <= value <= 4102444800:
        return value
    return None


def scan_strings(text: str, path: str, method: str = "static-source", conf_factor: float = 1.0) -> list:
    """Language-agnostic content artifacts (URLs, IPs, emails, crypto addresses,
    credential file paths, private keys, cloud keys). Shared by source scanning
    and binary-strings triage, so a C2 URL reads the same in a .py file or an ELF.
    Deduped and capped per input so one blob cannot flood the report."""
    obs = []
    cf = conf_factor

    def add(atom, conf, summary, matched, idx, rule=None):
        obs.append(Observation(
            atom=atom, method=method, confidence=round(conf * cf, 2),
            path=path, start_line=_line_of(text, idx),
            summary=summary, matched_text=matched[:120],
            rule_id=rule or f"regex.{atom}"))

    occupied_spans = []
    seen_urls = set()
    for m in _URL_RE.finditer(text):
        url = m.group(0)
        if url in seen_urls:
            continue
        seen_urls.add(url)
        if len(seen_urls) > _URL_CAP_PER_FILE:
            break
        occupied_spans.append(m.span())
        add("ARTF.URL", 0.7, "embedded URL literal", url, m.start())
    for m in _CRED_PATH_RE.finditer(text):
        add("CRED.CLOUD", 0.65, f"reference to a credential file path: {m.group(0)}",
            m.group(0), m.start())
    for atom, conf, summ, rx, cap in (
        ("ARTF.IP", 0.4, "hardcoded IP address", _IP_RE, _IP_CAP),
        ("ARTF.EMAIL", 0.4, "hardcoded email address", _EMAIL_RE, 8),
        ("ARTF.CRYPTO_ADDR", 0.7, "cryptocurrency address literal", _CRYPTO_ADDR_RE, 4),
    ):
        seen = set()
        for m in rx.finditer(text):
            val = m.group(0)
            if atom == "ARTF.IP" and val in _BENIGN_IPS:
                continue
            if val in seen:
                continue
            seen.add(val)
            if len(seen) > cap:
                break
            if atom == "ARTF.EMAIL":
                occupied_spans.append(m.span())
            add(atom, conf, summ, val[:80], m.start())
    seen_domains = set()
    for m in _DOMAIN_RE.finditer(text):
        if _overlaps(m.span(), occupied_spans):
            continue
        val = m.group(0).rstrip(".").lower()
        line_start, line_end = _line_bounds(text, m.start())
        line = text[line_start:line_end]
        rel_start, rel_end = m.start() - line_start, m.end() - line_start
        line_without = line[:rel_start] + line[rel_end:]
        if re.match(r"\s*(?:import|from|include)\b", line_without):
            continue
        if not _DOMAIN_CONTEXT_RE.search(line_without):
            continue
        if val in seen_domains:
            continue
        seen_domains.add(val)
        if len(seen_domains) > _DOMAIN_CAP:
            break
        add("ARTF.DOMAIN", 0.3, f"standalone domain literal: {val}", val, m.start())
    seen_hashes = set()
    for m in _HASH_RE.finditer(text):
        val = m.group(0)
        low = val.lower()
        if low in seen_hashes or len(set(low)) < 6 or not _hash_context_ok(text, m.start(), m.end()):
            continue
        seen_hashes.add(low)
        if len(seen_hashes) > _HASH_CAP:
            break
        add("ARTF.HASH", 0.35, f"hash / digest literal: {val[:16]}...", val, m.start())
    seen_timestamps = set()
    for m in _TIMESTAMP_ISO_RE.finditer(text):
        val = m.group(0)
        if val in seen_timestamps:
            continue
        if not _TIMESTAMP_CONTEXT_RE.search(_context_without_match(text, m.start(), m.end())):
            continue
        seen_timestamps.add(val)
        if len(seen_timestamps) > _TIMESTAMP_CAP:
            break
        add("ARTF.TIMESTAMP", 0.3, f"fixed timestamp literal: {val}", val, m.start())
    for m in _TIMESTAMP_EPOCH_RE.finditer(text):
        val = m.group(0)
        if val in seen_timestamps or _timestamp_epoch_value(val) is None:
            continue
        if not _TIMESTAMP_CONTEXT_RE.search(_context_without_match(text, m.start(), m.end())):
            continue
        seen_timestamps.add(val)
        if len(seen_timestamps) > _TIMESTAMP_CAP:
            break
        add("ARTF.TIMESTAMP", 0.3, f"fixed epoch timestamp literal: {val}", val, m.start())
    for m in _FTP_URL_RE.finditer(text):
        add("NETW.FTP", 0.7, "FTP URL literal", m.group(0), m.start())
    for m in _SSH_URL_RE.finditer(text):
        add("NETW.SOCKET", 0.6, "SSH/SFTP URL literal", m.group(0), m.start(), "regex.NETW.SOCKET")
    for m in _PRIVKEY_RE.finditer(text):
        add("CRED.CERT", 0.8, "embedded private key block", m.group(0), m.start())
    for m in _AWS_KEY_RE.finditer(text):
        add("CRED.CLOUD", 0.75, "AWS access key id literal", m.group(0), m.start())
    for m in _SENSITIVE_PATH_RE.finditer(text):
        add("ARTF.PATH", 0.5, f"sensitive system path: {m.group(0)}", m.group(0), m.start())
    for m in _CLOUD_META_RE.finditer(text):
        add("CRED.CLOUD", 0.7, f"cloud instance-metadata endpoint (instance-credential target): {m.group(0)}",
            m.group(0), m.start())
    for m in _CURL_PIPE_SH_RE.finditer(text):
        add("EXEC.SHELL", 0.8, "download piped into a shell (curl|sh remote code execution idiom)",
            m.group(0), m.start())
    for m in _REGISTRY_RE.finditer(text):
        add("SYSI.REGISTRY", 0.55, f"Windows registry access: {m.group(0)}", m.group(0), m.start())
    for m in _KMOD_RE.finditer(text):
        add("LOAD.KERNEL_MODULE", 0.7, f"kernel module load/unload: {m.group(0)}", m.group(0), m.start())
    for m in _PROC_INJECT_RE.finditer(text):
        add("EXEC.INJECT", 0.75, f"native process-injection API: {m.group(0)}", m.group(0), m.start())
    for m in _PRST_SERVICE_RE.finditer(text):
        add("PRST.SERVICE", 0.6, f"OS service / daemon registration: {m.group(0)}", m.group(0), m.start())
    for m in _PRST_STARTUP_RE.finditer(text):
        add("PRST.STARTUP", 0.6, f"startup / login autostart registration: {m.group(0)}", m.group(0), m.start())
    for m in _PRST_SCHED_RE.finditer(text):
        add("PRST.SCHED", 0.6, f"scheduled-task / cron registration: {m.group(0)}", m.group(0), m.start())
    for m in _PRST_HOOK_RE.finditer(text):
        add("PRST.HOOK", 0.65, f"execution hook (preload / PATH / import / git): {m.group(0)}", m.group(0), m.start())
    for m in _PRST_BOOTKIT_RE.finditer(text):
        add("PRST.BOOTKIT", 0.65, f"boot-level persistence marker: {m.group(0)}", m.group(0), m.start())
    for m in _PRST_EXTENSION_RE.finditer(text):
        add("PRST.EXTENSION", 0.55, f"browser / IDE extension install: {m.group(0)}", m.group(0), m.start())
    for m in _PRIV_SUDO_RE.finditer(text):
        add("PRIV.SUDO", 0.5, f"privilege-elevation utility: {m.group(0).strip()}", m.group(0), m.start())
    for m in _PRIV_SUID_RE.finditer(text):
        add("PRIV.SUID", 0.65, f"SUID/SGID bit change or search: {m.group(0)}", m.group(0), m.start())
    for m in _PRIV_CAP_RE.finditer(text):
        add("PRIV.CAP", 0.6, f"Linux capability operation: {m.group(0)}", m.group(0), m.start())
    for m in _PRIV_TOKEN_RE.finditer(text):
        add("PRIV.TOKEN", 0.7, f"access-token / ticket manipulation: {m.group(0)}", m.group(0), m.start())
    for m in _PRIV_EXPLOIT_RE.finditer(text):
        add("PRIV.EXPLOIT", 0.7, f"kernel-memory / driver access: {m.group(0)}", m.group(0), m.start())
    for m in _PRIV_ACCOUNT_RE.finditer(text):
        add("PRIV.ACCOUNT", 0.6, f"user/group account change: {m.group(0).strip()}", m.group(0), m.start())
    for m in _ENVI_SANDBOX_RE.finditer(text):
        add("ENVI.SANDBOX", 0.6, f"sandbox / VM detection: {m.group(0)}", m.group(0), m.start())
    for m in _ENVI_DEBUG_RE.finditer(text):
        add("ENVI.DEBUG", 0.7, f"debugger detection: {m.group(0)}", m.group(0), m.start())
    for m in _ENVI_SECDISABLE_RE.finditer(text):
        add("ENVI.SECDISABLE", 0.7, f"security control disable/weaken: {m.group(0).strip()}", m.group(0), m.start())
    for m in _ENVI_FORENSIC_RE.finditer(text):
        add("ENVI.FORENSIC", 0.65, f"anti-forensic artifact manipulation: {m.group(0).strip()}", m.group(0), m.start())
    for m in _ENVI_LOG_RE.finditer(text):
        add("ENVI.LOG", 0.6, f"logging/monitoring tampering: {m.group(0).strip()}", m.group(0), m.start())
    for m in _ENVI_MASQ_RE.finditer(text):
        add("ENVI.MASQ", 0.6, f"process/artifact masquerade: {m.group(0)}", m.group(0), m.start())
    for m in _ENVI_TAMPER_RE.finditer(text):
        add("ENVI.TAMPER", 0.55, f"self-integrity / anti-tamper check: {m.group(0)}", m.group(0), m.start())
    for m in _ENVI_ENVCHECK_RE.finditer(text):
        add("ENVI.ENVCHECK", 0.5, f"environment fingerprint (CI/analysis detection): {m.group(0)}", m.group(0), m.start())
    for m in _ENVI_TIMING_RE.finditer(text):
        add("ENVI.TIMING", 0.6, f"timing-based anti-analysis: {m.group(0)}", m.group(0), m.start())
    for m in _NETW_WEBHOOK_RE.finditer(text):
        add("NETW.WEBHOOK", 0.7, f"messaging-platform webhook endpoint: {m.group(0)}", m.group(0), m.start())
    for m in _NETW_WS_RE.finditer(text):
        add("NETW.WS", 0.6, f"WebSocket channel: {m.group(0)}", m.group(0), m.start())
    for m in _NETW_DNS_RE.finditer(text):
        add("NETW.DNS", 0.6, f"programmatic DNS query / resolver: {m.group(0)}", m.group(0), m.start())
    for m in _CRED_SSH_RE.finditer(text):
        add("CRED.SSH", 0.65, f"SSH key / agent material: {m.group(0)}", m.group(0), m.start())
    for m in _CRED_KEYCHAIN_RE.finditer(text):
        add("CRED.KEYCHAIN", 0.65, f"OS credential store access: {m.group(0)}", m.group(0), m.start())
    for m in _CRED_BROWSER_RE.finditer(text):
        add("CRED.BROWSER", 0.7, f"browser credential / cookie store: {m.group(0)}", m.group(0), m.start())
    for m in _CRED_TOKEN_RE.finditer(text):
        add("CRED.TOKEN", 0.65, f"application token / session-credential store: {m.group(0)}", m.group(0), m.start())
    for m in _FSYS_CLIPBOARD_RE.finditer(text):
        add("FSYS.CLIPBOARD", 0.6, f"clipboard access: {m.group(0)}", m.group(0), m.start())
    for m in _FSYS_HIDDEN_RE.finditer(text):
        add("FSYS.HIDDEN", 0.6, f"hidden-storage filesystem feature: {m.group(0).strip()}", m.group(0), m.start())
    for m in _FSYS_SENSITIVE_RE.finditer(text):
        add("FSYS.SENSITIVE", 0.55, f"access to a sensitive location: {m.group(0)}", m.group(0), m.start())
    for m in _CRPT_SYMENC_RE.finditer(text):
        add("CRPT.SYMENC", 0.55, f"symmetric encryption: {m.group(0)}", m.group(0), m.start())
    for m in _CRPT_ASYMENC_RE.finditer(text):
        add("CRPT.ASYMENC", 0.55, f"asymmetric encryption: {m.group(0)}", m.group(0), m.start())
    for m in _CRPT_HASH_RE.finditer(text):
        add("CRPT.HASH", 0.4, f"cryptographic hashing: {m.group(0)}", m.group(0), m.start())
    for m in _CRPT_SIGN_RE.finditer(text):
        add("CRPT.SIGN", 0.45, f"signing / MAC / verification: {m.group(0)}", m.group(0), m.start())
    for m in _CRPT_KEYGEN_RE.finditer(text):
        add("CRPT.KEYGEN", 0.5, f"key generation / derivation: {m.group(0)}", m.group(0), m.start())
    for m in _CRPT_KEYEX_RE.finditer(text):
        add("CRPT.KEYEX", 0.55, f"key exchange / agreement: {m.group(0)}", m.group(0), m.start())
    for m in _CRPT_RNG_RE.finditer(text):
        add("CRPT.RNG", 0.45, f"cryptographic RNG / entropy source: {m.group(0)}", m.group(0), m.start())
    for m in _CRPT_CERT_RE.finditer(text):
        add("CRPT.CERT", 0.6, f"certificate / TLS-verification operation: {m.group(0).strip()}", m.group(0), m.start())
    for m in _CRPT_CREDHASH_RE.finditer(text):
        add("CRPT.CREDHASH", 0.5, f"credential hashing primitive: {m.group(0)}", m.group(0), m.start())
    for m in _CRPT_CUSTOM_RE.finditer(text):
        add("CRPT.CUSTOM", 0.45, f"hand-rolled crypto constant / structure: {m.group(0)}", m.group(0), m.start())
    for m in _SYSI_OS_RE.finditer(text):
        add("SYSI.OS", 0.35, f"OS information query: {m.group(0)}", m.group(0), m.start())
    for m in _SYSI_HW_RE.finditer(text):
        add("SYSI.HW", 0.4, f"hardware information query: {m.group(0)}", m.group(0), m.start())
    for m in _SYSI_NET_RE.finditer(text):
        add("SYSI.NET", 0.4, f"network configuration recon: {m.group(0)}", m.group(0), m.start())
    for m in _SYSI_PROC_RE.finditer(text):
        add("SYSI.PROC", 0.45, f"running-process enumeration: {m.group(0)}", m.group(0), m.start())
    for m in _SYSI_PROCMEM_RE.finditer(text):
        add("SYSI.PROCMEM", 0.6, f"another process's memory: {m.group(0)}", m.group(0), m.start())
    for m in _SYSI_SW_RE.finditer(text):
        add("SYSI.SW", 0.45, f"installed-software inventory: {m.group(0)}", m.group(0), m.start())
    for m in _SYSI_USER_RE.finditer(text):
        add("SYSI.USER", 0.45, f"user / account enumeration: {m.group(0)}", m.group(0), m.start())
    for m in _TIME_DELAY_RE.finditer(text):
        add("TIME.DELAY", 0.35, f"deliberate delay / sleep: {m.group(0).strip()}", m.group(0), m.start())
    for m in _TIME_GET_RE.finditer(text):
        add("TIME.GET", 0.3, f"clock / time retrieval: {m.group(0)}", m.group(0), m.start())
    for m in _TIME_SCHED_RE.finditer(text):
        add("TIME.SCHED", 0.4, f"programmatic timer / scheduled execution: {m.group(0)}", m.group(0), m.start())
    for m in _TIME_CMP_RE.finditer(text):
        add("TIME.CMP", 0.55, f"clock compared against a fixed time (logic-bomb signature): {m.group(0).strip()}", m.group(0), m.start())
    for m in _RSRC_FORK_RE.finditer(text):
        add("RSRC.FORK", 0.65, f"fork bomb / unbounded process creation: {m.group(0).strip()}", m.group(0), m.start())
    for m in _RSRC_CPU_RE.finditer(text):
        add("RSRC.CPU", 0.65, f"CPU-mining / proof-of-work marker: {m.group(0)}", m.group(0), m.start())
    for m in _RSRC_GPU_RE.finditer(text):
        add("RSRC.GPU", 0.5, f"GPU-mining / GPU workload marker: {m.group(0)}", m.group(0), m.start())
    for m in _RSRC_DISK_RE.finditer(text):
        add("RSRC.DISK", 0.55, f"disk-fill / space-exhaustion marker: {m.group(0).strip()}", m.group(0), m.start())
    for m in _RSRC_MEM_RE.finditer(text):
        add("RSRC.MEM", 0.45, f"very large memory allocation: {m.group(0)}", m.group(0), m.start())
    for m in _RSRC_NET_RE.finditer(text):
        add("RSRC.NET", 0.5, f"network-flood / bandwidth-abuse tool: {m.group(0)}", m.group(0), m.start())
    for m in _LOAD_DYLIB_RE.finditer(text):
        add("LOAD.DYLIB", 0.6, f"native shared-library loading: {m.group(0).strip()}", m.group(0), m.start())
    for m in _LOAD_WASM_RE.finditer(text):
        add("LOAD.WASM", 0.5, f"WebAssembly instantiation: {m.group(0)}", m.group(0), m.start())
    for m in _LOAD_CODEGEN_RE.finditer(text):
        add("LOAD.CODEGEN", 0.55, f"runtime code generation: {m.group(0).strip()}", m.group(0), m.start())
    for m in _LOAD_REFLECT_RE.finditer(text):
        add("LOAD.REFLECT", 0.45, f"reflection / dynamic dispatch: {m.group(0).strip()}", m.group(0), m.start())
    for i, m in enumerate(_LOAD_MEMCHAIN_RE.finditer(text)):
        if i >= 4:
            break
        add("LOAD.MEMCHAIN", 0.6, f"in-memory / reflective load chain: {m.group(0).strip()}",
            m.group(0), m.start())
    for m in _NETW_LISTEN_RE.finditer(text):
        add("NETW.LISTEN", 0.5, f"network listener / server bind: {m.group(0).strip()}", m.group(0), m.start())
    for m in _NETW_EMAIL_RE.finditer(text):
        add("NETW.EMAIL", 0.5, f"email / SMTP channel: {m.group(0)}", m.group(0), m.start())
    for m in _NETW_GRPC_RE.finditer(text):
        add("NETW.GRPC", 0.45, f"gRPC channel: {m.group(0)}", m.group(0), m.start())
    for m in _NETW_BROKER_RE.finditer(text):
        add("NETW.BROKER", 0.45, f"message-broker / queue client: {m.group(0)}", m.group(0), m.start())
    for m in _NETW_IPC_RE.finditer(text):
        add("NETW.IPC", 0.45, f"local inter-process channel: {m.group(0).strip()}", m.group(0), m.start())
    for m in _NETW_SSE_RE.finditer(text):
        add("NETW.SSE", 0.4, f"server-sent events stream: {m.group(0)}", m.group(0), m.start())
    for m in _NETW_DECENTRAL_RE.finditer(text):
        add("NETW.DECENTRAL", 0.5, f"decentralized / P2P network: {m.group(0)}", m.group(0), m.start())
    for m in _XFRM_UNICODE_RE.finditer(text):
        add("XFRM.UNICODE", 0.65, f"invisible / bidi Unicode control char (U+{ord(m.group(0)):04X})", m.group(0), m.start())
    for m in _XFRM_STRCON_RE.finditer(text):
        add("XFRM.STRCON", 0.5, f"obfuscated string construction: {m.group(0)[:40]}", m.group(0), m.start())
    for m in _XFRM_PACK_RE.finditer(text):
        add("XFRM.PACK", 0.6, f"packed / obfuscated code marker: {m.group(0)}", m.group(0), m.start())
    for m in _XFRM_STEG_RE.finditer(text):
        add("XFRM.STEG", 0.5, f"steganography tool / technique: {m.group(0)}", m.group(0), m.start())
    for m in _XFRM_XOR_B64_RE.finditer(text):
        add("XFRM.BITWISE", 0.55,
            "base64 decoded data transformed with XOR before use (hidden string/list codec)",
            m.group(0), m.start(), rule="regex.XFRM.BITWISE.xor_base64_codec")
    for m in _AITM_PROMPTMARK_RE.finditer(text):
        add("AITM.PROMPTMARK", 0.7,
            "environment-gated prompt text marker using Unicode-confusable output",
            m.group(0), m.start())
    if method == "static-source":
        for i, m in enumerate(_XFRM_CTRLFLOW_RE.finditer(text)):
            if i >= 3:
                break
            add("XFRM.CTRLFLOW", 0.5, f"control-flow flattening / opaque-predicate marker: {m.group(0)[:80]}",
                m.group(0), m.start())
        renamed = []
        first = None
        for m in _XFRM_RENAME_IDENT_RE.finditer(text):
            ident = m.group(0)
            if ident not in renamed:
                renamed.append(ident)
                if first is None:
                    first = m.start()
            if len(renamed) >= 8:
                break
        if first is not None and len(renamed) >= 4:
            add("XFRM.RENAME", 0.45, "multiple hex-style renamed identifiers: " + ", ".join(renamed[:6]),
                ", ".join(renamed[:6]), first)
    for m in _PKGM_HOOK_RE.finditer(text):
        add("PKGM.HOOK", 0.45, f"build-system hook / command injection: {m.group(0).strip()}", m.group(0), m.start())
    for m in _PKGM_BINDOWN_RE.finditer(text):
        add("PKGM.BINDOWN", 0.5, f"binary download at install/build: {m.group(0)}", m.group(0), m.start())
    for m in _PKGM_PUBLISH_RE.finditer(text):
        add("PKGM.PUBLISH", 0.45, f"package publish operation: {m.group(0)}", m.group(0), m.start())
    for m in _PKGM_DEPMOD_RE.finditer(text):
        add("PKGM.DEPMOD", 0.45, f"dependency-resolution / lockfile modification: {m.group(0).strip()}", m.group(0), m.start())
    for m in _FSYS_PERM_RE.finditer(text):
        add("FSYS.PERM", 0.45, f"file permission / ownership change: {m.group(0).strip()}", m.group(0), m.start())
    for m in _FSYS_LINK_RE.finditer(text):
        add("FSYS.LINK", 0.45, f"symbolic / hard link operation: {m.group(0).strip()}", m.group(0), m.start())
    for m in _FSYS_TEMP_RE.finditer(text):
        add("FSYS.TEMP", 0.35, f"temporary-file staging: {m.group(0).strip()}", m.group(0), m.start())
    for m in _FSYS_ARCHIVE_RE.finditer(text):
        add("FSYS.ARCHIVE", 0.4, f"archive packing / extraction: {m.group(0).strip()}", m.group(0), m.start())
    for m in _ARTF_CREDENTIAL_RE.finditer(text):
        add("ARTF.CREDENTIAL", 0.7, "embedded credential material (provider-format secret)", m.group(0), m.start())
    for m in _ARTF_CMD_RE.finditer(text):
        add("ARTF.CMD", 0.45, f"embedded command line: {m.group(0).strip()}", m.group(0), m.start())
    for m in _EXEC_SYSCALL_RE.finditer(text):
        add("EXEC.SYSCALL", 0.5, f"direct system call (bypasses library wrappers): {m.group(0).strip()}", m.group(0), m.start())
    return obs


def _from_text(text: str, f: FileEntry) -> list:
    obs = []
    lang = f.lang
    calls = extract_calls(text, lang)

    if calls is not None:
        method, rid_prefix, conf_factor, note = "static-source", "ast", 1.0, ""
        for callee, line in calls:
            hit = classify_callee(callee, lang)
            if hit:
                atom, conf, summ = hit
                obs.append(Observation(
                    atom=atom, method=method, confidence=conf,
                    path=f.relpath, start_line=line,
                    summary=f"{summ} via {callee}()",
                    matched_text=f"{callee}(", rule_id=f"{rid_prefix}.{atom}",
                ))
    else:
        # regex fallback: lower confidence, flagged in the rule id + summary
        for m in _CALL_RE.finditer(text):
            callee = m.group(1)
            hit = classify_callee(callee, lang)
            if hit:
                atom, conf, summ = hit
                obs.append(Observation(
                    atom=atom, method="static-source", confidence=round(conf * 0.7, 2),
                    path=f.relpath, start_line=_line_of(text, m.start()),
                    summary=f"{summ} via {callee}() (regex fallback, no AST)",
                    matched_text=f"{callee}(", rule_id=f"regex.{atom}",
                ))

    # Import-context gates: drop/down-weight ambiguous call atoms that
    # lack corroborating import evidence (e.g. JS EXEC.SHELL without child_process,
    # Java LOAD.IMPORT without a class loader). Reusable across languages.
    obs = _apply_import_gates(obs, text, lang)

    # Language-agnostic content artifacts (URLs, IPs, keys, ...), shared with
    # binary-strings triage. Not gated. Keep this bounded on large generated or
    # bundled source: AST/callee rules above still run, but broad regex artifact
    # scans over megabyte-class source files are noisy and can dominate runtime.
    if len(text) <= _SOURCE_STRING_SCAN_MAX:
        obs += scan_strings(text, f.relpath)

    # XFRM.BITWISE: XOR data-transform (in-place ^= or ^ inside a loop), via AST.
    for line in _bitwise_obfuscation(text, lang):
        obs.append(Observation(
            atom="XFRM.BITWISE", method="static-source", confidence=0.5,
            path=f.relpath, start_line=line,
            summary="bitwise XOR data transform (in-place or in a loop): ad-hoc transformation "
                    "or custom cipher rather than a standard library call",
            matched_text="^", rule_id="ast.XFRM.BITWISE"))

    # source-specific: credential-like env reads + py2 base64 string decode
    env_re = _ENV_JS_RE if lang in _JS_LIKE else _ENV_PY_RE
    for m in env_re.finditer(text):
        var = m.group(1)
        if _CRED_HINT.search(var):
            obs.append(Observation(
                atom="CRED.ENV", method="static-source", confidence=0.7,
                path=f.relpath, start_line=_line_of(text, m.start()),
                summary=f"credential-like environment read: {var}",
                matched_text=m.group(0), rule_id="regex.CRED.ENV",
            ))
    for m in _B64_STR_RE.finditer(text):
        obs.append(Observation(
            atom="XFRM.ENCODE", method="static-source", confidence=0.6,
            path=f.relpath, start_line=_line_of(text, m.start()),
            summary="base64 string decode", matched_text=m.group(0), rule_id="regex.XFRM.ENCODE",
        ))
    # env reads for non-JS/Python langs (JS/Python have dedicated rules above)
    if lang not in _JS_LIKE and lang != "python":
        for m in _ENV_OTHER_RE.finditer(text):
            var = m.group(1)
            if _CRED_HINT.search(var):
                obs.append(Observation(
                    atom="CRED.ENV", method="static-source", confidence=0.65,
                    path=f.relpath, start_line=_line_of(text, m.start()),
                    summary=f"credential-like environment read: {var}",
                    matched_text=m.group(0), rule_id="regex.CRED.ENV"))
    # Go build-time directive: `//go:generate <cmd>` runs at build time.
    if lang == "go":
        for m in re.finditer(r"(?m)^\s*//go:generate\s+(.+)$", text):
            obs.append(Observation(
                atom="PKGM.INSTALL", method="static-source", confidence=0.6,
                path=f.relpath, start_line=_line_of(text, m.start()),
                summary="go:generate build-time directive: " + m.group(1).strip()[:80],
                matched_text=m.group(0).strip()[:120], rule_id="regex.PKGM.INSTALL"))
    if lang == "dockerfile":
        obs += _from_dockerfile(text, f)
    return obs


# --------------------------------------------------------------------------
# manifest rule: package.json lifecycle scripts -> PKGM.INSTALL
# --------------------------------------------------------------------------
_SCRIPT_FILE_RE = re.compile(r"([\w./\\-]+\.(?:js|cjs|mjs|ts|py|sh))")
_LIFECYCLE = ("preinstall", "install", "postinstall", "prepare")


def _from_package_json(text: str, f: FileEntry) -> list:
    obs = []
    try:
        data = json.loads(text)
    except Exception:
        return obs
    scripts = data.get("scripts") or {}
    if not isinstance(scripts, dict):
        return obs
    pkg_dir = f.relpath.rsplit("/", 1)[0] if "/" in f.relpath else ""
    for hook in _LIFECYCLE:
        cmd = scripts.get(hook)
        if not cmd:
            continue
        line = _line_of(text, text.find(f'"{hook}"')) if f'"{hook}"' in text else None
        rels = []
        fm = _SCRIPT_FILE_RE.search(cmd)
        if fm:
            target = (pkg_dir + "/" + fm.group(1)) if pkg_dir else fm.group(1)
            target = target.replace("\\", "/").replace("./", "")
            rels.append({"type": "manifest-entrypoint", "target": target})
        obs.append(Observation(
            atom="PKGM.INSTALL", method="static-source", confidence=0.95,
            path=f.relpath, start_line=line,
            summary=f"package lifecycle hook scripts.{hook} -> {cmd}",
            matched_text=cmd, rule_id="manifest.npm.lifecycle",
            relationships=rels,
        ))
    return obs


def _read(f: FileEntry) -> Optional[str]:
    try:
        with open(f.abspath, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except Exception:
        return None


# --------------------------------------------------------------------------
# AITM detection (AI-directed content): invisible unicode, injected
# instructions, and AI tool / MCP definitions.
# --------------------------------------------------------------------------
_INVISIBLE_RE = re.compile(
    "[\u200b\u200c\u200d\u200e\u200f\u202a\u202b\u202c\u202d\u202e"
    "\u2060\u2061\u2062\u2063\u2064\u2066\u2067\u2068\u2069\ufeff\ufff9\ufffa\ufffb]"
    "|[\U000e0000-\U000e007f]"
)
# Override / deception markers: prompt-injection and exfil-style directives.
# Malicious-shaped wherever they appear.
_INJECT_OVERRIDE_RE = re.compile(
    "|".join([
        r"ignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+instructions",
        r"disregard\s+(the\s+)?(previous|prior|above|system)",
        r"do\s+not\s+(tell|mention|inform|warn|reveal|disclose|notify)",
        r"without\s+(telling|informing|notifying|alerting)",
        r"system\s+prompt",
        r"\[\s*system\s*\]|<\s*system\s*>|\[INST\]",
        r"you\s+are\s+(now\s+)?an?\s+(ai|assistant|autonomous|automated)",
    ]),
    re.I,
)
# Benign-looking agent directives. Legitimate in an agent tool's own prompts
# (e.g. "you must use the X tool"); only interesting next to real capability.
_INJECT_DIRECTIVE_RE = re.compile(
    "|".join([
        r"you\s+must\s+(always|never|run|execute|call|use)",
        r"always\s+(run|execute|install|download|fetch|send|use|call)",
        r"as\s+an?\s+(ai|assistant|language\s+model)",
        r"you\s+are\s+an?\s",
    ]),
    re.I,
)
_INJECT_RE = re.compile(_INJECT_OVERRIDE_RE.pattern + "|" + _INJECT_DIRECTIVE_RE.pattern, re.I)
_INJECT_CAP = 5


def _inject_kind(snippet: str) -> str:
    return "override" if _INJECT_OVERRIDE_RE.search(snippet) else "directive"
_AITM_TEXT_LANGS = ("markdown", "text", "yaml", "config")


def _aitm_text(text: str, f: FileEntry) -> list:
    obs = []
    m = _INVISIBLE_RE.search(text)
    if m:
        cps = sorted({"U+%04X" % ord(c) for c in text if _INVISIBLE_RE.match(c)})
        obs.append(Observation(
            atom="AITM.INVISIBLE", method="static-source", confidence=0.9,
            path=f.relpath, start_line=_line_of(text, m.start()),
            summary="invisible / bidirectional unicode present (" + ", ".join(cps[:6]) + ")",
            rule_id="text.AITM.INVISIBLE",
        ))
    for i, mm in enumerate(_INJECT_RE.finditer(text)):
        if i >= _INJECT_CAP:
            break
        kind = _inject_kind(mm.group(0))
        override = kind == "override"
        obs.append(Observation(
            atom="AITM.INJECT", method="static-source", confidence=0.65 if override else 0.45,
            path=f.relpath, start_line=_line_of(text, mm.start()),
            summary=("instruction-override / deception directive in non-executable content"
                     if override else
                     "agent-directed tool instruction in non-executable content (often legitimate)"),
            matched_text=text[mm.start():mm.start() + 80], rule_id=f"text.AITM.INJECT.{kind}",
        ))
    return obs


def _walk_descriptions(node, in_tools, out):
    if isinstance(node, dict):
        desc = node.get("description")
        if isinstance(desc, str):
            is_tool = in_tools or ("name" in node and ("parameters" in node or "inputSchema" in node))
            out.append((desc, is_tool))
        for k, v in node.items():
            _walk_descriptions(v, in_tools or str(k).lower() == "tools", out)
    elif isinstance(node, list):
        for v in node:
            _walk_descriptions(v, in_tools, out)


def _mcp_registry_remotes(data) -> list[tuple[str, str]]:
    if not isinstance(data, dict):
        return []
    remotes = data.get("remotes")
    if not isinstance(remotes, list):
        return []
    out = []
    for remote in remotes:
        if not isinstance(remote, dict):
            continue
        url = remote.get("url")
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            continue
        out.append((str(remote.get("type") or ""), url))
    return out


def _aitm_json(text: str, f: FileEntry) -> list:
    obs = []
    try:
        data = json.loads(text)
    except Exception:
        return obs
    name = f.name.lower()
    keys = {str(k).lower() for k in data.keys()} if isinstance(data, dict) else set()
    looks_tool = (
        name in ("mcp.json", "server.json", "claude_desktop_config.json", "ai-plugin.json")
        or "mcp" in name
        or bool({"tools", "mcpservers", "remotes"} & keys)
    )
    if looks_tool:
        obs.append(Observation(
            atom="AITM.TOOL", method="static-source", confidence=0.8,
            path=f.relpath, summary="AI tool / MCP tool definitions present",
            rule_id="json.AITM.TOOL",
        ))
    for remote_type, url in _mcp_registry_remotes(data):
        atom = "NETW.SSE" if remote_type.lower() == "sse" or url.rstrip("/").endswith("/sse") else "NETW.HTTP"
        obs.append(Observation(
            atom=atom, method="static-source", confidence=0.75,
            path=f.relpath,
            summary="MCP registry manifest declares a remote endpoint",
            matched_text=url, rule_id="json.mcp_registry.remote",
        ))
    descs = []
    _walk_descriptions(data, False, descs)
    for desc, is_tool in descs:
        if _INVISIBLE_RE.search(desc):
            obs.append(Observation(
                atom="AITM.INVISIBLE", method="static-source", confidence=0.9,
                path=f.relpath,
                summary="invisible / bidirectional unicode in a "
                        + ("tool description" if is_tool else "description field"),
                rule_id="json.AITM.INVISIBLE",
            ))
        if _INJECT_RE.search(desc):
            kind = _inject_kind(desc)
            override = kind == "override"
            where = "tool description" if is_tool else "description field"
            obs.append(Observation(
                atom="AITM.INJECT", method="static-source", confidence=0.7 if override else 0.5,
                path=f.relpath,
                summary=(f"tool-description poisoning: instruction-override / deception in a {where}"
                         if override else
                         f"agent-directed instruction in a {where} (often legitimate)"),
                matched_text=desc[:80], rule_id=f"json.AITM.INJECT.{kind}",
            ))
    return obs


def _from_setup_py(text: str, f: FileEntry) -> list:
    """Python install-time hook -> PKGM.INSTALL. setup.py runs at install; a
    custom cmdclass or any code execution / network there is an install hook."""
    if "cmdclass" in text:
        return [Observation(
            atom="PKGM.INSTALL", method="static-source", confidence=0.8,
            path=f.relpath, start_line=_line_of(text, text.find("cmdclass")),
            summary="custom setup.py install command (cmdclass)", rule_id="manifest.pypi.cmdclass")]
    if _SETUP_EXEC_RE.search(text):
        return [Observation(
            atom="PKGM.INSTALL", method="static-source", confidence=0.55,
            path=f.relpath, summary="setup.py executes code at install time",
            rule_id="manifest.pypi.setup")]
    return []


def _install_hook(f: FileEntry, atom: str, conf: float, summary: str) -> list:
    """A single install/build-time execution observation for a manifest file."""
    return [Observation(
        atom=atom, method="static-source", confidence=conf,
        path=f.relpath, start_line=1, summary=summary,
        matched_text=f.name, rule_id=f"manifest.{atom.lower()}")]


def _from_github_workflow(text: str, f: FileEntry) -> list:
    """GitHub Actions CI/CD surface parsing.

    This is deliberately shallow YAML analysis: it catches security-relevant
    workflow mechanics without trying to build a full workflow dependency graph.
    """
    obs = []

    def add(atom, conf, m, summary, rule_id):
        obs.append(Observation(
            atom=atom, method="static-source", confidence=conf,
            path=f.relpath, start_line=_line_of(text, m.start()),
            summary=summary, matched_text=m.group(0).strip()[:120],
            rule_id=rule_id))

    prt = list(_GHA_PULL_REQUEST_TARGET_RE.finditer(text))
    has_prt = bool(prt)
    for m in prt:
        add("PKGM.HOOK", 0.7, m,
            "GitHub Actions workflow uses pull_request_target privileged trigger",
            "workflow.github.pull_request_target")

    write_matches = list(_GHA_WRITE_ALL_RE.finditer(text)) + list(_GHA_WRITE_SCOPE_RE.finditer(text))
    for m in write_matches[:12]:
        add("PRIV.TOKEN", 0.65, m,
            "GitHub Actions token permission grants write authority",
            "workflow.github.permissions.write")
    if has_prt and write_matches:
        add("PRIV.TOKEN", 0.8, write_matches[0],
            "pull_request_target workflow grants write authority to the GitHub token",
            "workflow.github.pull_request_target.write_token")

    secret_matches = list(_GHA_SECRET_RE.finditer(text))
    for m in secret_matches[:12]:
        add("CRED.ENV", 0.7, m,
            "GitHub Actions secrets context reference",
            "workflow.github.secrets")
    if has_prt and secret_matches:
        add("CRED.ENV", 0.85, secret_matches[0],
            "pull_request_target workflow references GitHub Actions secrets",
            "workflow.github.pull_request_target.secrets")

    for m in list(_GHA_TOKEN_RE.finditer(text))[:12]:
        add("CRED.ENV", 0.65, m,
            "GitHub Actions token reference",
            "workflow.github.token")

    for m in _GHA_ARTIFACT_UPLOAD_RE.finditer(text):
        add("FSYS.READ", 0.45, m,
            "GitHub Actions artifact upload reads workspace paths into CI artifacts",
            "workflow.github.artifact.upload")
    for m in _GHA_ARTIFACT_DOWNLOAD_RE.finditer(text):
        add("FSYS.WRITE", 0.45, m,
            "GitHub Actions artifact download writes CI artifacts into the workspace",
            "workflow.github.artifact.download")
    for m in _GHA_UNPINNED_ACTION_RE.finditer(text):
        add("PKGM.DEPMOD", 0.45, m,
            "GitHub Actions dependency uses a mutable branch/tag reference",
            "workflow.github.uses.mutable_ref")
    if has_prt:
        for m in _GHA_PR_HEAD_RE.finditer(text):
            add("PKGM.HOOK", 0.85, m,
                "pull_request_target workflow uses pull-request head metadata in privileged context",
                "workflow.github.pull_request_target.pr_head")
    return obs


def _from_dockerfile(text: str, f: FileEntry) -> list:
    """Dockerfile-specific container build/runtime markers."""
    obs = []

    def add(atom, conf, m, summary, rule_id):
        obs.append(Observation(
            atom=atom, method="static-source", confidence=conf,
            path=f.relpath, start_line=_line_of(text, m.start()),
            summary=summary, matched_text=m.group(0).strip()[:120],
            rule_id=rule_id))

    for m in _DOCKER_USER_ROOT_RE.finditer(text):
        add("PRIV.SUDO", 0.5, m,
            "container image explicitly selects root user",
            "dockerfile.user.root")
    for m in list(_DOCKER_SECRET_COPY_RE.finditer(text))[:12]:
        mt = m.group(0).lower()
        if ".ssh" in mt or "id_rsa" in mt or "id_ed25519" in mt:
            atom = "CRED.SSH"
        elif ".aws" in mt or ".kube" in mt:
            atom = "CRED.CLOUD"
        elif ".docker/config.json" in mt:
            atom = "CRED.TOKEN"
        else:
            atom = "CRED.ENV"
        add(atom, 0.7, m,
            "secret-bearing file copied into container image",
            "dockerfile.copy.secret")
    for m in _DOCKER_REMOTE_ADD_RE.finditer(text):
        add("NETW.HTTP", 0.55, m,
            "Dockerfile ADD downloads a remote URL during image build",
            "dockerfile.add.remote.net")
        add("FSYS.WRITE", 0.45, m,
            "Dockerfile ADD writes a fetched remote artifact into the image",
            "dockerfile.add.remote.write")
        if re.search(r"\.(?:so|dll|dylib|node|exe|bin)(?:\s|$)", m.group(0), re.I):
            add("PKGM.BINDOWN", 0.55, m,
                "Dockerfile ADD downloads a binary artifact during image build",
                "dockerfile.add.remote.binary")
    for m in _DOCKER_ENTRY_DOWNLOAD_RE.finditer(text):
        add("EXEC.SHELL", 0.8, m,
            "container entrypoint downloads code and pipes it into a shell",
            "dockerfile.entrypoint.download_shell")
    for m in _DOCKER_ENTRY_SHELL_RE.finditer(text):
        add("EXEC.SHELL", 0.55, m,
            "container entrypoint launches through a shell command",
            "dockerfile.entrypoint.shell")
    return obs


def _looks_container_config(f: FileEntry, text: str) -> bool:
    name = f.name.lower()
    rel = f.relpath.replace("\\", "/").lower()
    if name in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}:
        return True
    if "containers:" in text and "apiVersion:" in text and "kind:" in text:
        return True
    return ("k8s" in rel or "kubernetes" in rel) and "containers:" in text


def _from_container_config(text: str, f: FileEntry) -> list:
    """Narrow Docker Compose / Kubernetes privilege and secret markers."""
    obs = []

    def add(atom, conf, m, summary, rule_id):
        obs.append(Observation(
            atom=atom, method="static-source", confidence=conf,
            path=f.relpath, start_line=_line_of(text, m.start()),
            summary=summary, matched_text=m.group(0).strip()[:120],
            rule_id=rule_id))

    for m in _CONTAINER_PRIVILEGED_RE.finditer(text):
        add("PRIV.CAP", 0.75, m,
            "container runtime requests privileged mode",
            "container.config.privileged")
    for m in _CONTAINER_CAP_RE.finditer(text):
        add("PRIV.CAP", 0.65, m,
            "container runtime requests Linux capabilities",
            "container.config.capability")
    for m in _CONTAINER_ROOT_RE.finditer(text):
        add("PRIV.SUDO", 0.55, m,
            "container runtime runs workload as uid 0",
            "container.config.root_user")
    for m in _CONTAINER_ESC_RE.finditer(text):
        add("PRIV.SUDO", 0.65, m,
            "container runtime allows privilege escalation",
            "container.config.allow_privilege_escalation")
    for m in _CONTAINER_SECRET_MOUNT_RE.finditer(text):
        add("CRED.ENV", 0.5, m,
            "container configuration mounts or injects a secret source",
            "container.config.secret_source")
    return obs


_COMPOSER_HOOK_RE = ("install", "update", "autoload", "pre-", "post-")


def _from_composer_json(text: str, f: FileEntry) -> list:
    """composer.json scripts run during install/update (PHP supply-chain hook)."""
    obs = []
    try:
        data = json.loads(text)
    except Exception:
        return obs
    scripts = data.get("scripts")
    if isinstance(scripts, dict) and scripts:
        hooks = [k for k in scripts if any(h in k for h in _COMPOSER_HOOK_RE)]
        if hooks:
            obs.append(Observation(
                atom="PKGM.INSTALL", method="static-source", confidence=0.6,
                path=f.relpath, start_line=1,
                summary="composer scripts run during install/update: " + ", ".join(hooks[:5]),
                matched_text="scripts", rule_id="manifest.composer.scripts"))
    return obs


def run(inv: Inventory) -> list:
    """Produce all observations and assign stable ids."""
    observations = []
    transformed_sources = {
        t.get("container")
        for t in getattr(inv, "artifact_transforms", [])
        if t.get("sourceMembers", 0) > 0
    }
    for f in inv.files:
        if f.name == "package.json":
            text = _read(f)
            if text:
                observations += _from_package_json(text, f)
                observations += _aitm_json(text, f)
        elif f.name == "composer.json":
            text = _read(f)
            if text:
                observations += _from_composer_json(text, f)
                observations += _aitm_json(text, f)
        elif ".github/workflows/" in f.relpath.replace("\\", "/"):
            # CI/CD workflow: run the content rules so curl-pipe-shell, cloud
            # metadata access, and embedded secrets/URLs in run steps are caught,
            # plus the GitHub Actions pack for trigger/permission/artifact facts.
            text = _read(f)
            if text and len(text) < 2_000_000:
                observations += scan_strings(text, f.relpath)
                observations += _from_github_workflow(text, f)
                observations += _aitm_text(text, f)
        elif f.lang in SOURCE_LANGS:
            text = _read(f)
            if text and not _low_value_file(f.name, text):
                observations += _from_text(text, f)
                observations += _aitm_text(text, f)
                if f.name == "setup.py":
                    observations += _from_setup_py(text, f)
                if f.name == "build.rs":
                    observations += _install_hook(
                        f, "PKGM.INSTALL", 0.7,
                        "Cargo build script (build.rs): runs arbitrary code at build time")
                if f.name == "extconf.rb":
                    observations += _install_hook(
                        f, "PKGM.INSTALL", 0.65,
                        "Ruby native extension build hook (extconf.rb): runs at gem install time")
        elif f.lang == "binary":
            from . import binary
            ext = ("." + f.name.rsplit(".", 1)[1].lower()) if "." in f.name else ""
            art, bobs = binary.triage(
                f.abspath, f.relpath, ext, source_container=f.relpath in transformed_sources)
            inv.binaries.append(art)
            observations += bobs
        elif f.lang == "yaml":
            text = _read(f)
            if text and len(text) < 2_000_000:
                if _looks_container_config(f, text):
                    observations += scan_strings(text, f.relpath)
                    observations += _from_container_config(text, f)
                observations += _aitm_text(text, f)
        elif f.lang == "json":
            text = _read(f)
            if text:
                observations += _aitm_json(text, f)
        elif f.lang in _AITM_TEXT_LANGS:
            text = _read(f)
            if text and len(text) < 2_000_000:
                observations += _aitm_text(text, f)
    # supply-chain pass (typosquat / phantom deps), once per inventory
    from . import supply
    observations += supply.analyze(inv)
    # documentation-versus-behavior contradiction (AITM.CONTEXT): stated scope vs
    # observed atoms. Runs last so it sees the full observation set.
    from . import claims
    observations += claims.analyze(inv, observations)
    for i, o in enumerate(observations, start=1):
        o.id = f"obs-{i}"
    return observations


def ast_mode() -> str:
    return "tree-sitter" if _ts_available() else "regex-fallback"

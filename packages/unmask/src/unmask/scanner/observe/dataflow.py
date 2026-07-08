"""Intra-file dataflow: upgrade single-file co-occurrence to a PROVEN path.

Lightweight taint tracking over the tree-sitter AST. A value derived from a
*source* (a secret read, a fetch, a decode, an enumerated path set, a network
target, a trust disablement) that reaches a *sink* (network egress, a file
write/delete, code exec, encryption) is a proven path. The compose layer reads
these facts and raises confidence only when a path is proven; unproven findings
stay at same-file co-occurrence confidence. No false upgrades.

Scope (honest): JavaScript/TypeScript and Python — the deepest-supported,
highest-value languages here. Taint is file-flat, and only single-assignment
variables carry taint into a proof, which avoids the main false-link case (a
name reused in another scope). Cross-function reachability lives in callgraph.py.
This reads source; it never executes it.
"""

from __future__ import annotations

from unmask.scanner.observe.callee import (
    _GRAMMAR, _callee_text, _field, _node_children, _node_kind, _node_line,
    _node_text, _parser, _v, ts_available,
)

DATAFLOW_LANGS = {"javascript", "typescript", "tsx", "python"}

_ASSIGN_KINDS = {
    "variable_declarator",              # JS: const x = ...
    "assignment_expression",            # JS: x = ...
    "augmented_assignment_expression",  # JS: x += ...
    "assignment",                       # Python: x = ...
    "augmented_assignment",             # Python: x += ...
}
_CALL_KINDS = {"call_expression", "call"}
_FUNC_KINDS = {
    "arrow_function", "function", "function_declaration", "function_expression",
    "function_definition", "method_definition", "lambda", "generator_function",
    "generator_function_declaration",
}

# (source kind, sink kind) -> (finding kind, human shape). A proven path exists
# when a source-tainted value reaches a sink of the paired kind.
_PROVEN = {
    ("secret", "egress"): ("exfil", "secret -> egress"),
    ("sensitive", "egress"): ("exfil", "sensitive read -> egress"),
    ("decode", "exec"): ("decode-exec", "decode -> exec"),
    ("fetch", "exec"): ("dropper", "fetch -> exec"),
    ("fetch", "write"): ("dropper", "fetch -> write"),
    ("decode", "write"): ("dropper", "decode -> write"),
    ("pathset", "encrypt"): ("ransom", "enumerated path -> encryption"),
    ("pathset", "write"): ("ransom", "enumerated path -> write"),
    ("pathset", "delete"): ("ransom", "enumerated path -> delete"),
    ("target", "egress"): ("propagation", "discovered target -> network action"),
    ("target", "exec"): ("propagation", "discovered target -> command execution"),
    ("target", "write"): ("propagation", "discovered target -> file staging"),
    ("trust-disable", "egress"): ("mitm", "trust disablement -> network operation"),
}


def _source_kinds(text: str):
    t = text.lower()
    out = set()
    if "process.env" in t or "os.environ" in t or "os.getenv" in t or "getenv(" in t:
        out.add("secret")
    if (
        any(p in t for p in ("readfile", "readfilesync", "read_text", "read_bytes", "open("))
        and any(p in t for p in (
            "/.ssh/", "/.aws/", "/.azure/", "/.config/gcloud/", "/.gnupg/",
            "wallet.dat", "keystore", "/.docker/config.json", "/.kube/config",
            "/proc/", "/etc/passwd", "/etc/shadow", "/etc/sudoers",
        ))
    ):
        out.add("sensitive")
    if any(p in t for p in ("pyperclip.paste", "get-clipboard", "getclipboarddata", "navigator.clipboard")):
        out.add("sensitive")
    if any(p in t for p in ("http.get", "https.get", "http.request", "https.request",
                            "fetch(", "axios", "got(", "requests.get", "requests.request",
                            "urlopen", "urllib.request")):
        out.add("fetch")
    if ("atob(" in t or "b64decode" in t or "unhexlify" in t or "fromhex" in t
            or ("buffer.from(" in t and ("base64" in t or "hex" in t))):
        out.add("decode")
    if any(p in t for p in (
        "readdirsync", "readdir(", "os.listdir", "os.scandir", "glob.glob",
        ".glob(", ".rglob(", "os.walk", "find ", "findstr ",
    )):
        out.add("pathset")
    if any(p in t for p in (
        "os.networkinterfaces", "getifaddrs", "ip addr", "ipconfig", "ifconfig",
        "arp -a", "netstat", "route print", "socket.gethostbyname", "dns.resolve",
        "dns.lookup", "nmap", "/proc/net/",
    )):
        out.add("target")
    if _trust_disable_text(t):
        out.add("trust-disable")
    return out


def _sink_kinds(callee: str):
    c = callee.lower()
    seg = c.rsplit(".", 1)[-1]
    out = set()
    if (seg in {"eval", "exec", "execsync", "spawn", "spawnsync", "system", "popen", "function"}
            or "child_process" in c or "subprocess" in c or "os.system" in c
            or seg in {"runinthiscontext", "runincontext"}):
        out.add("exec")
    if (seg in {"writefile", "writefilesync", "write_text", "write_bytes"}
            or "fs.write" in c or "createwritestream" in c):
        out.add("write")
    if seg in {"unlink", "unlinksync", "remove", "rmdir", "rm", "rmsync"}:
        out.add("delete")
    if ("encrypt" in c or "cryptojs.aes" in c or "createcipher" in c
            or "fernet" in c or "cipher.getinstance" in c):
        out.add("encrypt")
    if (any(p in c for p in ("http.get", "https.get", "http.request", "https.request",
                             "requests.post", "requests.put", "requests.get", "socket.send",
                             "urlopen", "axios")) or seg == "sendto"):
        out.add("egress")
    return out


def _trust_disable_text(text: str):
    t = text.lower().replace(" ", "")
    return any(p in t for p in (
        "verify=false",
        "rejectunauthorized:false",
        "ssl.cert_none",
        "_create_unverified_context",
        "check_hostname=false",
        "node_tls_reject_unauthorized",
        "insecureskipverify:true",
    ))


def _gate_kind(text: str):
    t = text.lower()
    time_gate = any(p in t for p in (
        "date.now", "new date", "time.time", "datetime.now", "datetime.utcnow",
        "system.currenttimemillis", "time.now",
    ))
    env_gate = any(p in t for p in (
        "process.env", "os.environ", "os.getenv", "getenv(", "platform.",
        "sys.platform", "os.platform", "hostname", "uname", "ci", "github_actions",
        "docker", "container", "virtualbox", "vmware", "sandbox",
    ))
    if time_gate:
        return "time-gate"
    if env_gate:
        return "environment-gate"
    return None


def _walk(root):
    stack = [root]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(_node_children(n))


def _identifiers(node, data):
    """Identifier names referenced in a subtree, NOT descending into nested
    functions (so a call's arguments do not slurp a callback body)."""
    out, stack = set(), [(node, True)]
    while stack:
        n, root = stack.pop()
        if _node_kind(n) == "identifier":
            out.add(_node_text(n, data))
        if _node_kind(n) in _FUNC_KINDS and not root:
            continue
        for c in _node_children(n):
            stack.append((c, False))
    return out


def _calls_without_nested(node):
    """Call nodes under `node`, not descending into a nested named/anon function."""
    out, stack = [], [node]
    while stack:
        n = stack.pop()
        k = _node_kind(n)
        if k in _FUNC_KINDS and n is not node:
            continue
        if k in _CALL_KINDS:
            out.append(n)
            continue
        stack.extend(_node_children(n))
    return out


def _arg_calls(node):
    """Every call node inside `node` (a sink's argument subtree), descending THROUGH
    nested calls (so `exec(fetch(u).read())` yields both `fetch(u).read()` and
    `fetch(u)`) but not into nested function bodies. Used to detect a source flowing
    into a sink by call STRUCTURE, not by substring — a source name inside a string
    literal or passed as a bare value is not a call and is correctly ignored."""
    out, stack = [], [node]
    while stack:
        n = stack.pop()
        k = _node_kind(n)
        if k in _FUNC_KINDS:
            continue
        if k in _CALL_KINDS:
            out.append(n)
        stack.extend(_node_children(n))
    return out


def _returns_without_nested(fn_node):
    """The value-producing expressions of `fn_node`: an arrow's expression body, or
    every `return` in a block body — never descending into a nested function."""
    body = _field(fn_node, "body")
    if body is None:
        return []
    if _node_kind(body) not in ("statement_block", "block"):
        return [body]  # arrow with expression body: the body IS the returned value
    out, stack = [], [body]
    while stack:
        n = stack.pop()
        k = _node_kind(n)
        if k in _FUNC_KINDS and n is not body:
            continue  # a return inside a nested callback is not this function's return
        if k == "return_statement":
            out.append(n)
            continue
        stack.extend(_node_children(n))
    return out


def _collect_source_fns(root, data):
    """Map user function name -> the source kinds its RETURN value carries (a 1-level
    summary). `def fetch(u): return urlopen(u).read()` -> {"fetch": {"fetch"}}. Lets the
    sink loop treat `exec(fetch(url))` as fetch->exec even though the download hides in a
    helper. File-flat like the rest of this pass; keyed by name."""
    fns: dict[str, set] = {}
    for n in _walk(root):
        k = _node_kind(n)
        name_node = fn_node = None
        if k in ("function_declaration", "function_definition",
                 "generator_function_declaration", "method_definition"):
            name_node, fn_node = _field(n, "name"), n
        elif k == "variable_declarator":  # const fetch = (u) => https.get(u)
            val = _field(n, "value")
            if val is not None and _node_kind(val) in _FUNC_KINDS:
                name_node, fn_node = _field(n, "name"), val
        if name_node is None or fn_node is None or _node_kind(name_node) != "identifier":
            continue
        kinds: set = set()
        for expr in _returns_without_nested(fn_node):
            kinds |= _source_kinds(_node_text(expr, data))
        if kinds:
            name = _node_text(name_node, data)
            fns[name] = fns.get(name, set()) | kinds
    return fns


def _target_text(node, data):
    tgt = _field(node, "name", "left")
    return _node_text(tgt, data).strip() if tgt is not None else ""


def _receiver_from_attr(text: str):
    text = (text or "").strip()
    for suffix in (".verify", ".check_hostname"):
        if text.lower().endswith(suffix):
            return text[: -len(suffix)].strip()
    return ""


def prove_paths(src: str, lang: str):
    """Return a list of proven-path dicts for one file's source, or []."""
    if not ts_available() or lang not in DATAFLOW_LANGS:
        return []
    grammar = _GRAMMAR.get(lang, lang)
    try:
        parser = _parser(grammar)
        try:
            tree = parser.parse(src)
        except TypeError:
            tree = parser.parse(src.encode("utf-8"))
    except Exception:
        return []
    data = src.encode("utf-8")
    root = _v(tree, "root_node")

    assigns, calls, branch_proofs = [], [], []
    assign_count, trust_disabled_receivers = {}, set()
    for n in _walk(root):
        k = _node_kind(n)
        if k in _ASSIGN_KINDS:
            tgt, rhs = _field(n, "name", "left"), _field(n, "value", "right")
            target_text = _target_text(n, data)
            if rhs is not None and _receiver_from_attr(target_text):
                rhs_text = _node_text(rhs, data).strip().lower()
                if rhs_text in {"false", "0"} or _trust_disable_text(f"{target_text}={rhs_text}"):
                    trust_disabled_receivers.add(_receiver_from_attr(target_text))
            if tgt is not None and rhs is not None and _node_kind(tgt) == "identifier":
                name = _node_text(tgt, data)
                assigns.append((name, rhs))
                assign_count[name] = assign_count.get(name, 0) + 1
        elif k in _CALL_KINDS:
            calls.append((_callee_text(n, data).strip(), _field(n, "arguments"),
                          _node_line(n), _node_text(n, data)))
        elif k == "if_statement":
            cond = _field(n, "condition")
            gate = _gate_kind(_node_text(cond, data)) if cond is not None else None
            if not gate:
                continue
            for call in _calls_without_nested(n):
                # The call list includes any call in the condition itself. Ignore
                # those: we want payloads reached by the branch, not the gate.
                if cond is not None and _v(cond, "start_byte") <= _v(call, "start_byte") <= _v(cond, "end_byte"):
                    continue
                sinks = _sink_kinds(_callee_text(call, data).strip())
                for sk in sorted(sinks & {"exec", "egress", "write", "delete"}):
                    branch_proofs.append({
                        "kind": "gated-payload",
                        "shape": f"{gate} -> {sk}",
                        "variable": "branch condition",
                        "sourceKind": gate,
                        "sinkKind": sk,
                        "line": _node_line(call),
                    })

    # 1-level function summary: a helper whose return value carries a source lets a
    # call to it act as that source (exec(fetch(u)) where fetch() downloads).
    source_fns = _collect_source_fns(root, data)

    # taint fixpoint: only single-assignment variables carry taint (precision guard)
    taint: dict[str, set] = {}
    for _ in range(8):
        changed = False
        for name, rhs in assigns:
            if assign_count.get(name) != 1:
                continue
            rhs_text = _node_text(rhs, data)
            rhs_low = rhs_text.lower()
            kinds = set(_source_kinds(rhs_text))
            for v in _identifiers(rhs, data):
                if v != name and assign_count.get(v) == 1:
                    inherited = set(taint.get(v, set()))
                    # A path set consumed by a read/encrypt becomes content, not a
                    # path set anymore — drop the pathset taint at that hop.
                    if "pathset" in inherited and any(p in rhs_low for p in (
                        "readfile", "read_text", "read_bytes", "open(", "encrypt", "cryptojs",
                    )):
                        inherited.discard("pathset")
                    kinds |= inherited
            if kinds - taint.get(name, set()):
                taint[name] = taint.get(name, set()) | kinds
                changed = True
        if not changed:
            break

    seen, paths = set(), []
    for p in branch_proofs:
        key = (p["kind"], p["sourceKind"], p["sinkKind"], p["line"])
        if key not in seen:
            seen.add(key)
            paths.append(p)
    for callee, args, line, call_text in calls:
        sks = _sink_kinds(callee)
        if "egress" in sks and _trust_disable_text(call_text):
            key = ("mitm", "call option", line)
            if key not in seen:
                seen.add(key)
                paths.append({"kind": "mitm", "shape": "trust disablement -> network operation",
                              "variable": "call option", "sourceKind": "trust-disable",
                              "sinkKind": "egress", "line": line})
        receiver = callee.split(".", 1)[0] if "." in callee else ""
        if "egress" in sks and receiver in trust_disabled_receivers:
            key = ("mitm", receiver, line)
            if key not in seen:
                seen.add(key)
                paths.append({"kind": "mitm", "shape": "trust-disabled session -> network operation",
                              "variable": receiver, "sourceKind": "trust-disable",
                              "sinkKind": "egress", "line": line})
        if not sks or args is None:
            continue
        matched_sinks: set = set()  # sink kinds already proven for THIS call (via a var)
        # (parity-locked) a single-assignment tainted variable used as an argument.
        for v in _identifiers(args, data):
            if assign_count.get(v) != 1:
                continue
            for src_kind in taint.get(v, set()):
                for sk in sks:
                    hit = _PROVEN.get((src_kind, sk))
                    if not hit:
                        continue
                    kind, shape = hit
                    key = (kind, v, line)
                    if key not in seen:
                        seen.add(key)
                        paths.append({"kind": kind, "shape": shape, "variable": v,
                                      "sourceKind": src_kind, "sinkKind": sk, "line": line})
                    matched_sinks.add(sk)
        # A source that flows in via a CALL in the args, matched structurally (not by
        # substring over the arg text, which would fire on a source name inside a string
        # literal or a bare value passed as an argument):
        #   - a source-returning HELPER actually called here, e.g. exec(fetch(u))  [all kinds]
        #   - a DIRECT source call, e.g. exec(urlopen(u).read())  [fetch only: decode-inline
        #     stays BP-OBFEXEC co-occurrence, preserving the frozen oracle]
        arg_kinds: set = set()
        for call in _arg_calls(args):
            callee = _callee_text(call, data).strip()
            arg_kinds |= source_fns.get(callee, set())
            if "." in callee:
                arg_kinds |= source_fns.get(callee.rsplit(".", 1)[-1], set())
            arg_kinds |= _source_kinds(callee + "(") & {"fetch"}
        for src_kind in arg_kinds:
            for sk in sks:
                if sk in matched_sinks:   # already proven via a variable for this call
                    continue
                hit = _PROVEN.get((src_kind, sk))
                if not hit:
                    continue
                kind, shape = hit
                key = (kind, "call", line)
                if key not in seen:
                    seen.add(key)
                    paths.append({"kind": kind, "shape": shape, "variable": "call argument",
                                  "sourceKind": src_kind, "sinkKind": sk, "line": line})
    return paths


def analyze_inventory(inv, only_paths=None) -> dict:
    """Run prove_paths over the inventory's source files (optionally only those in
    `only_paths`). Returns {relpath: [proven-path dicts]} for files with a path."""
    out = {}
    for f in getattr(inv, "files", []):
        lang = getattr(f, "language", None)
        if lang not in DATAFLOW_LANGS:
            continue
        if only_paths is not None and f.rel not in only_paths:
            continue
        try:
            with open(f.path, encoding="utf-8", errors="replace") as fh:
                src = fh.read()
        except Exception:
            continue
        found = prove_paths(src, lang)
        if found:
            out[f.rel] = found
    return out

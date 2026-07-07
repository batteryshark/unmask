"""Cross-function / cross-file reachability.

Builds a local call graph over the package's JS/TS/Python source: which function
calls which, resolving local calls and relative imports across files. Then, from
the package entry points (every module's top-level code, which runs on import),
it computes which MCD sink-bearing functions are reachable and over what call
chain. This catches a chain SPLIT across files that no single-file co-occurrence
finding would see (a fetch in one module, an exec in another, wired by the entry).

Calls it cannot follow (computed/dynamic dispatch, unresolved imports) are counted
as reachability gaps, not silently dropped. Best-effort, read-only, never executes.
Scope: JS/TS/Python; arrow/lambda functions bound to a name are attributed to the
enclosing scope (a known limitation, stated in the report).
"""

from __future__ import annotations

import os
import re

from unmask.scanner.observe.callee import (
    _GRAMMAR, _callee_text, _field, _node_children, _node_kind, _node_text,
    _parser, _v, ts_available,
)
from unmask.scanner.observe.dataflow import DATAFLOW_LANGS, _sink_kinds

# Named function-definition node kinds are separate graph nodes; anonymous
# arrows/expressions are attributed to their enclosing scope.
_DEF_KINDS = {"function_declaration", "function_definition", "method_definition",
              "generator_function_declaration"}

_MAX_FUNCS = 4000

# import-map regexes (pragmatic; import syntax is regular). name -> spec or (spec,name).
_JS_REQUIRE = re.compile(r"""(?:const|let|var)\s+(\w+)\s*=\s*require\(\s*["']([^"']+)["']\s*\)""")
_JS_REQUIRE_DESTRUCT = re.compile(r"""(?:const|let|var)\s*\{([^}]+)\}\s*=\s*require\(\s*["']([^"']+)["']\s*\)""")
_JS_IMPORT_NAMED = re.compile(r"""import\s*\{([^}]+)\}\s*from\s*["']([^"']+)["']""")
_JS_IMPORT_DEFAULT = re.compile(r"""import\s+(\w+)\s+from\s*["']([^"']+)["']""")
_JS_IMPORT_NS = re.compile(r"""import\s*\*\s*as\s+(\w+)\s+from\s*["']([^"']+)["']""")
_PY_FROM = re.compile(r"""^\s*from\s+([.\w]+)\s+import\s+([^\n#]+)""", re.MULTILINE)
_PY_IMPORT = re.compile(r"""^\s*import\s+([.\w]+)(?:\s+as\s+(\w+))?""", re.MULTILINE)


def _import_map(src: str, lang: str):
    """name -> ('module', spec) | ('named', spec, original_name)."""
    m = {}
    if lang == "python":
        for spec, names in _PY_FROM.findall(src):
            for raw in names.split(","):
                nm = raw.strip().split(" as ")[-1].strip()
                orig = raw.strip().split(" as ")[0].strip()
                if nm:
                    m[nm] = ("named", spec, orig)
        for spec, alias in _PY_IMPORT.findall(src):
            m[alias or spec.split(".")[-1]] = ("module", spec)
        return m
    for nm, spec in _JS_REQUIRE.findall(src):
        m[nm] = ("module", spec)
    for names, spec in _JS_REQUIRE_DESTRUCT.findall(src):
        for raw in names.split(","):
            nm = raw.strip().split(":")[0].split(" as ")[-1].strip()
            orig = raw.strip().split(":")[0].split(" as ")[0].strip()
            if nm:
                m[nm] = ("named", spec, orig)
    for names, spec in _JS_IMPORT_NAMED.findall(src):
        for raw in names.split(","):
            nm = raw.strip().split(" as ")[-1].strip()
            orig = raw.strip().split(" as ")[0].strip()
            if nm:
                m[nm] = ("named", spec, orig)
    for nm, spec in _JS_IMPORT_DEFAULT.findall(src):
        m.setdefault(nm, ("module", spec))
    for nm, spec in _JS_IMPORT_NS.findall(src):
        m[nm] = ("module", spec)
    return m


def _resolve_spec(spec: str, importer_rel: str, file_set):
    """Resolve a relative module spec to a file relpath in the package, or None."""
    base = os.path.dirname(importer_rel)
    if spec.startswith("."):
        if spec.startswith("./") or spec.startswith("../"):
            root = os.path.normpath(os.path.join(base, spec))
        else:  # python relative: ".helper" -> sibling
            root = os.path.normpath(os.path.join(base, spec.lstrip(".").replace(".", "/")))
        cands = [root + e for e in (".js", ".ts", ".mjs", ".py")] + \
                [os.path.join(root, i) for i in ("index.js", "index.ts", "__init__.py")]
    else:  # bare sibling (python `import helper`, or pkg.mod)
        rel = spec.replace(".", "/")
        cands = [rel + ".py", os.path.join(base, rel + ".py"),
                 os.path.join(rel, "__init__.py"), rel + ".js", os.path.join(base, rel + ".js")]
    for c in cands:
        c = os.path.normpath(c)
        if c in file_set:
            return c
    return None


def _collect_functions(root, data):
    """Return (functions, module_calls). functions: list of (name, body_node);
    module_calls: calls at top level (outside any named def)."""
    functions, module_calls = [], []
    stack = [(root, True)]
    while stack:
        n, top = stack.pop()
        k = _node_kind(n)
        if k in _DEF_KINDS:
            name_node = _field(n, "name")
            body = _field(n, "body")
            if name_node is not None and body is not None:
                functions.append((_node_text(name_node, data), body))
            continue  # do not descend; its calls belong to it
        if k in ("call_expression", "call") and top:
            module_calls.append(n)
        for c in _node_children(n):
            stack.append((c, top))
    return functions, module_calls


def _calls_in(body, data):
    """Call nodes in a scope, descending into anonymous closures but not named defs."""
    out, stack = [], [body]
    while stack:
        n = stack.pop()
        k = _node_kind(n)
        if k in _DEF_KINDS and n is not body:
            continue
        if k in ("call_expression", "call"):
            out.append(n)
        for c in _node_children(n):
            stack.append(c)
    return out


def _classify_call(node, data, importer_rel, imap, file_set, funcs_by_file):
    """Return (resolved_func_id | None, sink_kinds, is_unresolved_edge). Only a
    relative (in-package) import that fails to resolve, or a computed/dynamic call,
    counts as an unresolved edge. External modules are leaves, not gaps."""
    callee = _callee_text(node, data).strip()
    sinks = _sink_kinds(callee)
    if not callee:
        return None, sinks, False
    if "[" in callee:                              # computed / dynamic dispatch
        return None, sinks, True
    if "." in callee:
        base, _, method = callee.rpartition(".")
        binding = imap.get(base)
        if binding and binding[0] == "module" and binding[1].startswith("."):
            tf = _resolve_spec(binding[1], importer_rel, file_set)
            if tf and method in funcs_by_file.get(tf, ()):
                return f"{tf}::{method}", sinks, False
            return None, sinks, True               # in-package import we could not follow
        return None, sinks, False                  # external module / unknown base: leaf
    # bare name: a local function, or a named import
    if callee in funcs_by_file.get(importer_rel, ()):
        return f"{importer_rel}::{callee}", sinks, False
    binding = imap.get(callee)
    if binding and binding[0] == "named" and binding[1].startswith("."):
        tf = _resolve_spec(binding[1], importer_rel, file_set)
        if tf and binding[2] in funcs_by_file.get(tf, ()):
            return f"{tf}::{binding[2]}", sinks, False
        return None, sinks, True
    return None, sinks, False


def analyze(inv) -> dict:
    """Build the call graph and report MCD sinks reachable from package entries."""
    files = [f for f in getattr(inv, "files", []) if getattr(f, "language", None) in DATAFLOW_LANGS]
    if not ts_available() or not files:
        return {}

    file_set = {f.rel for f in files}
    parsed = {}      # relpath -> (functions list, module_calls, import_map, data)
    funcs_by_file = {}
    for f in files:
        try:
            with open(f.path, encoding="utf-8", errors="replace") as fh:
                src = fh.read()
            parser = _parser(_GRAMMAR.get(f.language, f.language))
            try:
                tree = parser.parse(src)
            except TypeError:
                tree = parser.parse(src.encode("utf-8"))
        except Exception:
            continue
        data = src.encode("utf-8")
        functions, module_calls = _collect_functions(_v(tree, "root_node"), data)
        parsed[f.rel] = (functions, module_calls, _import_map(src, f.language), data)
        funcs_by_file[f.rel] = {name for name, _ in functions}

    # build nodes: each named function + a per-file "<module>" node (an entry)
    edges, sink_kinds, unresolved = {}, {}, 0
    nodes = set()
    for rel, (functions, module_calls, imap, data) in parsed.items():
        if len(nodes) > _MAX_FUNCS:
            break
        mod_id = f"{rel}::<module>"
        nodes.add(mod_id)
        scopes = [(mod_id, module_calls)] + [(f"{rel}::{name}", _calls_in(body, data))
                                             for name, body in functions]
        for fid, calls in scopes:
            nodes.add(fid)
            edges.setdefault(fid, set())
            sk = set()
            for call in calls:
                tgt, s, unres = _classify_call(call, data, rel, imap, file_set, funcs_by_file)
                sk |= s
                if tgt:
                    edges[fid].add(tgt)
                elif unres:
                    unresolved += 1
            if sk:
                sink_kinds[fid] = sk

    # BFS from all module entries; record a parent chain
    entries = [n for n in nodes if n.endswith("::<module>")]
    parent = {e: None for e in entries}
    queue = list(entries)
    while queue:
        cur = queue.pop(0)
        for nxt in edges.get(cur, ()):
            if nxt not in parent:
                parent[nxt] = cur
                queue.append(nxt)

    reachable_sinks = []
    for fid, sk in sink_kinds.items():
        if fid.endswith("::<module>") or fid not in parent:
            continue  # module-direct sinks are intra-file co-occurrence; skip unreached
        chain, cur = [], fid
        while cur is not None:
            chain.append(cur)
            cur = parent.get(cur)
        chain.reverse()
        entry_file = chain[0].split("::", 1)[0]
        sink_file = fid.split("::", 1)[0]
        reachable_sinks.append({
            "file": sink_file,
            "function": fid.split("::", 1)[1],
            "sinkKinds": sorted(sk),
            "entryFile": entry_file,
            "chain": chain,
            "crossFile": entry_file != sink_file,
        })
    reachable_sinks.sort(key=lambda r: (not r["crossFile"], r["file"]))

    if not reachable_sinks and not unresolved:
        return {}
    return {
        "reachableSinks": reachable_sinks,
        "unresolvedEdges": unresolved,
        "functions": len(nodes),
        "note": ("Reachability over a best-effort call graph (JS/TS/Python; relative imports "
                 "resolved). Unresolved edges are computed/dynamic dispatch and unresolved imports; "
                 "arrow/lambda functions bound to a name are attributed to the enclosing scope."),
    }

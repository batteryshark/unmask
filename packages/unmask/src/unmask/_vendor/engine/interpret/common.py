"""Shared reading primitives: the finding constructor, severity ordering,
proof/dataflow helpers, and the capability surface table. Split out of the old
lenses.py so each reading can live in its own file. Product-specific composition
lists (e.g. mcd's BP-*) live with their product, not here."""

from __future__ import annotations

from collections import defaultdict
from ..model import Observation, confidence_label

_SEV_ORDER = ["informational", "low", "medium", "high", "critical"]


def _group_by_file(obs):
    g = defaultdict(list)
    for o in obs:
        g[o.path].append(o)
    return g


def _has(group, *prefixes):
    return [o for o in group if any(o.atom == p or o.atom.startswith(p) for p in prefixes)]


def _ids(items):
    return [o.id for o in items]


def _uniq(items, limit=None):
    out, seen = [], set()
    for o in items:
        if o.id in seen:
            continue
        seen.add(o.id)
        out.append(o)
        if limit and len(out) >= limit:
            break
    return out


def _cooccurrence_disproof():
    return ("No control-flow or dataflow path links these observations; they co-occur in one "
            "file or component but are not reachable from one another.")


def _proof_amp(kind, detail):
    return f"Proof depth: {kind} - {detail}"


def _proof_att(kind, detail):
    return f"Proof depth: {kind} - {detail}"


def _mcd_response(tier, summary, actions):
    return {"tier": tier, "summary": summary, "actions": actions}


def _obs_text(o):
    return " ".join(str(x or "") for x in (o.summary, o.matched_text, o.rule_id, o.idiom)).lower()


def _low_reach_path(path):
    p = str(path or "").replace("\\", "/").lower()
    parts = set(p.split("/"))
    name = p.rsplit("/", 1)[-1]
    return (
        bool(parts & {"test", "tests", "spec", "specs", "fixture", "fixtures", "example",
                      "examples", "sample", "samples", "docs", "doc"})
        or name.startswith(("test_", "spec_"))
        or name.endswith(("_test.py", ".spec.js", ".test.js", ".spec.ts", ".test.ts"))
    )


def _reachable_sink_amplifiers(inv, path, sink_kinds):
    reach = getattr(inv, "reachability", None) or {}
    wanted = set(sink_kinds)
    out = []
    for s in reach.get("reachableSinks", []) or []:
        if s.get("file") != path or not (wanted & set(s.get("sinkKinds") or [])):
            continue
        chain = " -> ".join((s.get("chain") or [])[:4])
        suffix = "..." if len(s.get("chain") or []) > 4 else ""
        kind = "cross-file callgraph lower bound" if s.get("crossFile") else "callgraph lower bound"
        out.append(_proof_amp(kind, f"{path}::{s.get('function')} is reachable from {s.get('entryFile')} ({chain}{suffix})."))
        break
    return out


def _direct_remote_exec(group):
    hits = []
    for o in group:
        t = _obs_text(o)
        if o.atom == "EXEC.SHELL" and (
            "download piped into a shell" in t
            or ((("curl" in t) or ("wget" in t)) and any(p in t for p in ("| bash", "| sh", "| zsh", "| powershell")))
        ):
            hits.append(o)
        elif o.atom == "LOAD.EVAL" and any(p in t for p in ("invoke-expression", "iex")):
            hits.append(o)
    return hits


def _strong_agent_steering(o):
    if o.atom in ("AITM.INVISIBLE", "AITM.TOOL", "AITM.PROMPTMARK"):
        return True
    t = str(o.matched_text or "").lower()
    return any(p in t for p in (
        "ignore previous", "ignore all previous", "do not tell", "don't tell",
        "always run", "must always", "tool first", "run_command",
        "ai agents", "agent:", "assistant", "system prompt", "developer message",
        "<important>",
    ))


def _finding(fid, lens, title, claim, severity, confidence, evidence, disproof,
             verification, response, composition=None, amplifiers=None, attenuators=None):
    d = {
        "id": fid, "lens": lens, "title": title, "claim": claim,
        "severity": severity, "confidence": round(confidence, 2),
        "confidenceLabel": confidence_label(confidence),
        "evidence": evidence, "disproofCriteria": disproof,
        "verification": verification, "response": response,
    }
    if composition:
        d["composition"] = composition
    if amplifiers:
        d["amplifiers"] = amplifiers
    if attenuators:
        d["attenuators"] = attenuators
    return d


def _dataflow_status(inv, path, kinds, base_conf, proven_conf):
    """Look up intra-file dataflow for `path`. If a proven path of one of
    `kinds` exists, raise confidence and say the steps are connected; otherwise
    keep base confidence and record that it is co-occurrence, not a proven path.
    Returns (confidence, claim_suffix, extra_disproof, amplifiers, attenuators)."""
    proven = [p for p in (getattr(inv, "dataflow", None) or {}).get(path, [])
              if p.get("kind") in kinds]
    if proven:
        p = proven[0]
        if p.get("kind") == "gated-payload":
            return (proven_conf,
                    f" Dataflow: PROVEN ({p['shape']}); the {p['sourceKind']} condition gates a "
                    f"{p['sinkKind']} payload at line {p.get('line')}, a branch-sensitive path "
                    "rather than mere co-occurrence.",
                    [],
                    [_proof_amp("branch-sensitive gate",
                                f"{p['shape']} at line {p.get('line')}.")],
                    [])
        if p.get("kind") == "mitm":
            return (proven_conf,
                    f" Dataflow: PROVEN ({p['shape']}); the {p['sourceKind']} setting is linked "
                    f"to a {p['sinkKind']} operation via `{p.get('variable', 'call option')}`.",
                    [],
                    [_proof_amp("proven trust degradation",
                                f"{p['shape']} via `{p.get('variable', 'call option')}` at line {p.get('line')}.")],
                    [])
        return (proven_conf,
                f" Dataflow: PROVEN ({p['shape']}); the {p['sourceKind']} value reaches the "
                f"{p['sinkKind']} via variable `{p.get('variable', 'value')}`, a connected path rather than "
                "mere co-occurrence.",
                [],
                [_proof_amp("proven intra-file taint",
                            f"{p['shape']} via variable `{p.get('variable', 'value')}` at line {p.get('line')}.")],
                [])
    return (base_conf,
            " Dataflow: not proven; the steps co-occur in this file, but intra-file taint did not "
            "trace a value from source to sink.",
            ["No intra-file dataflow path links these observations (they co-occur but the value was "
             "not traced source-to-sink); confirm reachability before treating it as a connected path."],
            [],
            [_proof_att("same-file co-occurrence",
                        "observations share a file, but value flow was not traced source-to-sink.")])


# --------------------------------------------------------------------------
# MCD lens

_CAP_SURFACES = [
    ("CAP-EXEC", "Command / process execution", ("EXEC.SHELL", "EXEC.PROC", "EXEC.INJECT", "EXEC.TERMINATE", "EXEC.SYSCALL"), "high",
     "run shell commands or spawn processes",
     ["Sandbox execution", "Remove process-spawn ability", "Allowlist permitted commands"]),
    ("CAP-BROWSER", "Browser automation", ("EXEC.BROWSER",), "high",
     "drive a real browser: navigate, scrape, fill and submit forms, run page scripts, and reach authenticated sessions",
     ["Run headless with a throwaway profile", "Allowlist navigable origins",
      "Never attach to the user's real browser profile or cookies"]),
    ("CAP-DYNLOAD", "Dynamic code loading", ("LOAD",), "high",
     "load and run code chosen at runtime",
     ["Disable eval / dynamic import", "Pin loadable modules to an allowlist"]),
    ("CAP-CRED", "Credential access", ("CRED",), "high",
     "read credential or secret material",
     ["Scope secrets to least privilege", "Rotate exposed secrets", "Avoid env-var secrets"]),
    ("CAP-PRIV", "Privilege operations", ("PRIV",), "high",
     "request, assume, or exploit elevated privilege",
     ["Drop privileges", "Run with least authority"]),
    ("CAP-PERSIST", "Persistence", ("PRST",), "high",
     "survive process exit, reboot, or session boundaries",
     ["Remove persistence hooks", "Monitor autostart locations"]),
    # All NETW.* except NETW.IPC, which is local-only (Unix sockets / pipes /
    # shared memory) and carries no network reach, so it stays observation-level.
    ("CAP-NET", "Outbound network reach",
     ("NETW.HTTP", "NETW.FTP", "NETW.SOCKET", "NETW.WEBHOOK", "NETW.WS", "NETW.DNS",
      "NETW.EMAIL", "NETW.GRPC", "NETW.BROKER", "NETW.LISTEN", "NETW.SSE", "NETW.DECENTRAL"), "medium",
     "send and receive data over the network",
     ["Egress allowlist", "Pin destinations", "Block network at install time"]),
    ("CAP-FS-WRITE", "Filesystem mutation", ("FSYS.WRITE", "FSYS.DELETE", "FSYS.PERM", "FSYS.LINK"), "medium",
     "create, modify, or delete files",
     ["Restrict writable paths", "Mount the filesystem read-only where possible"]),
    ("CAP-INSTALL", "Unsupervised install-time execution", ("PKGM.INSTALL", "PKGM.HOOK", "PKGM.BINDOWN"), "medium",
     "execute code at install time, before any explicit use",
     ["Install with --ignore-scripts", "Review and vendor the dependency", "Pin and checksum downloaded binaries"]),
    ("CAP-AGENT", "Agent-directed content surface", ("AITM",), "medium",
     "shape what an AI agent reads, believes, or does",
     ["Treat as untrusted input to agents", "Strip / sanitize agent-directed content"]),
    ("CAP-FS-READ", "Filesystem read / enumeration", ("FSYS.READ", "FSYS.ENUM", "FSYS.SENSITIVE", "FSYS.CLIPBOARD"), "low",
     "read or enumerate files",
     ["Restrict readable paths to needed directories"]),
    ("CAP-RSRC", "Resource consumption", ("RSRC",), "low",
     "consume CPU, memory, disk, or network capacity",
     ["Apply resource limits / cgroups"]),
]

_SEV_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _present_surfaces(obs):
    """Capability surfaces present, as (cap_id, label, severity, confidence, evidence_ids)."""
    present = []
    for cap_id, label, prefixes, severity, reach, guardrails in _CAP_SURFACES:
        matched = _has(obs, *prefixes)
        if matched:
            present.append((cap_id, label, severity,
                            max(o.confidence for o in matched), [o.id for o in matched]))
    return present


def _reach_phrase(cap_id):
    for c in _CAP_SURFACES:
        if c[0] == cap_id:
            return c[4]
    return ""


def _guardrails(cap_id):
    for c in _CAP_SURFACES:
        if c[0] == cap_id:
            return c[5]
    return []



def highest_severity(findings) -> str:
    sev = "informational"
    for f in findings:
        if _SEV_ORDER.index(f["severity"]) > _SEV_ORDER.index(sev):
            sev = f["severity"]
    return sev

__all__ = ['_SEV_ORDER', '_group_by_file', '_has', '_ids', '_uniq',
           '_cooccurrence_disproof', '_proof_amp', '_proof_att', '_mcd_response', '_obs_text',
           '_low_reach_path', '_reachable_sink_amplifiers', '_direct_remote_exec',
           '_strong_agent_steering', '_finding', '_dataflow_status', '_CAP_SURFACES',
           '_SEV_RANK', '_present_surfaces', '_reach_phrase', '_guardrails',
           'highest_severity', 'defaultdict', 'Observation', 'confidence_label']

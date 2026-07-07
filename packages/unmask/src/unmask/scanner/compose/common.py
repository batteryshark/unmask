"""Shared reading primitives for compose: the finding constructor, severity
ordering, and proof/dataflow helpers. Ported from the reference
`engine.interpret.common`, adapted to the native Observation (evidence instead of
matched_text; no idiom).

Dataflow/reachability degrade gracefully: when the inventory carries no `dataflow`
or `reachability` (the source-observe slice does not yet compute them), findings
fall back to same-file co-occurrence confidence — which is exactly what the
reference produced for the corpus, so this is parity, not a shortcut.
"""

from __future__ import annotations

from collections import defaultdict

_SEV_ORDER = ["informational", "low", "medium", "high", "critical"]
_SEV_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def confidence_label(c: float) -> str:
    if c >= 0.75:
        return "high"
    if c >= 0.45:
        return "medium"
    return "low"


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
    return " ".join(str(x or "") for x in (o.summary, o.evidence, o.rule_id)).lower()


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
        out.append(_proof_amp(kind, f"{path}::{s.get('function')} is reachable from "
                                    f"{s.get('entryFile')} ({chain}{suffix})."))
        break
    return out


def _direct_remote_exec(group):
    hits = []
    for o in group:
        t = _obs_text(o)
        if o.atom == "EXEC.SHELL" and (
            "download piped into a shell" in t
            or ((("curl" in t) or ("wget" in t))
                and any(p in t for p in ("| bash", "| sh", "| zsh", "| powershell")))
        ):
            hits.append(o)
        elif o.atom == "LOAD.EVAL" and any(p in t for p in ("invoke-expression", "iex")):
            hits.append(o)
    return hits


def _strong_agent_steering(o):
    if o.atom in ("AITM.INVISIBLE", "AITM.TOOL", "AITM.PROMPTMARK"):
        return True
    t = str(o.evidence or "").lower()
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
    """Intra-file dataflow for `path`: proven path of one of `kinds` → raise
    confidence; else base confidence + co-occurrence note. Returns
    (confidence, claim_suffix, extra_disproof, amplifiers, attenuators)."""
    proven = [p for p in (getattr(inv, "dataflow", None) or {}).get(path, [])
              if p.get("kind") in kinds]
    if proven:
        p = proven[0]
        if p.get("kind") == "gated-payload":
            return (proven_conf,
                    f" Dataflow: PROVEN ({p['shape']}); the {p['sourceKind']} condition gates a "
                    f"{p['sinkKind']} payload at line {p.get('line')}, a branch-sensitive path "
                    "rather than mere co-occurrence.",
                    [], [_proof_amp("branch-sensitive gate", f"{p['shape']} at line {p.get('line')}.")], [])
        if p.get("kind") == "mitm":
            return (proven_conf,
                    f" Dataflow: PROVEN ({p['shape']}); the {p['sourceKind']} setting is linked "
                    f"to a {p['sinkKind']} operation via `{p.get('variable', 'call option')}`.",
                    [], [_proof_amp("proven trust degradation",
                                    f"{p['shape']} via `{p.get('variable', 'call option')}` at line {p.get('line')}.")], [])
        return (proven_conf,
                f" Dataflow: PROVEN ({p['shape']}); the {p['sourceKind']} value reaches the "
                f"{p['sinkKind']} via variable `{p.get('variable', 'value')}`, a connected path rather than "
                "mere co-occurrence.",
                [], [_proof_amp("proven intra-file taint",
                                f"{p['shape']} via variable `{p.get('variable', 'value')}` at line {p.get('line')}.")], [])
    return (base_conf,
            " Dataflow: not proven; the steps co-occur in this file, but intra-file taint did not "
            "trace a value from source to sink.",
            ["No intra-file dataflow path links these observations (they co-occur but the value was "
             "not traced source-to-sink); confirm reachability before treating it as a connected path."],
            [], [_proof_att("same-file co-occurrence",
                            "observations share a file, but value flow was not traced source-to-sink.")])


__all__ = [
    "_SEV_ORDER", "_SEV_RANK", "confidence_label", "_group_by_file", "_has", "_ids",
    "_uniq", "_cooccurrence_disproof", "_proof_amp", "_proof_att", "_mcd_response",
    "_obs_text", "_low_reach_path", "_reachable_sink_amplifiers", "_direct_remote_exec",
    "_strong_agent_steering", "_finding", "_dataflow_status",
]

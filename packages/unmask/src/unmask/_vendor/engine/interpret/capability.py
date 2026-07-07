"""The capability reading: blast radius if the code is abused, compromised, or confused."""

from __future__ import annotations

from .common import *  # noqa: F401,F403 (shared finding/severity/proof helpers)

def capability(obs, inv=None) -> list:
    findings = []
    present = _present_surfaces(obs)
    n = 0
    for cap_id, label, severity, conf, ev in present:
        n += 1
        findings.append(_finding(
            f"cap-{n}", "capability", f"{label} capable",
            f"This component can {_reach_phrase(cap_id)}. Blast radius if abused, compromised, or manipulated: "
            f"{severity}. (Capability, not malice: benign code has capabilities too.)",
            severity, conf, ev,
            disproof=[
                "The matched code is dead / unreferenced / never invoked.",
                "The call is gated behind a condition that is never true in practice.",
            ],
            verification=[
                {"question": f"Is the {label.lower()} capability reachable from an entry point or external input?",
                 "method": "static-source", "reason": "A capability only matters if it is reachable."},
            ],
            response={"summary": "Reduce blast radius: " + _guardrails(cap_id)[0].lower() + ".",
                      "actions": _guardrails(cap_id)},
            composition=cap_id,
            attenuators=["Bounded if invoked only on explicit user action and against fixed, documented targets."],
        ))

    if not present:
        return findings

    ids = {c[0] for c in present}
    by_id = {c[0]: c for c in present}
    amps = []
    if "CAP-NET" in ids and ("CAP-CRED" in ids or "CAP-FS-READ" in ids):
        amps.append("CR-EXFIL: exfiltration-capable: can collect sensitive data and send it off-host.")
    if "CAP-NET" in ids and ("CAP-EXEC" in ids or "CAP-DYNLOAD" in ids):
        amps.append("CR-RCE: remote-execution-capable: network input plus code execution in one component.")
    if "CAP-FS-WRITE" in ids and ("CAP-EXEC" in ids or "CAP-DYNLOAD" in ids):
        amps.append("CR-SELFMOD: self-modifying-capable: can write files and execute code.")
    if "CAP-INSTALL" in ids and ({"CAP-EXEC", "CAP-DYNLOAD", "CAP-NET", "CAP-FS-WRITE"} & ids):
        amps.append("CR-INSTALL-AUTH: install-time authority: capabilities run unsupervised before explicit use.")
    if "CAP-AGENT" in ids and ({"CAP-EXEC", "CAP-DYNLOAD", "CAP-NET", "CAP-CRED"} & ids):
        amps.append("CR-AGENT-RISK: agent-directed content sits next to real capability (see decisions lens).")

    def combo(comp, title, claim, severity, need_ids, control):
        nonlocal n
        chosen = [by_id[i] for i in need_ids if i in by_id]
        if len(chosen) != len(need_ids):
            return
        n += 1
        ev = []
        conf = 0.0
        for s in chosen:
            ev.extend(s[4][:3])
            conf = max(conf, s[3])
        findings.append(_finding(
            f"cap-{n}", "capability", title, claim,
            severity, min(0.85, round(conf, 2)), ev,
            disproof=[
                "The surfaces are not mutually reachable or cannot be used in the same execution path.",
                "Existing controls bound one side of the composition (sandbox, egress allowlist, read-only filesystem, approval gate).",
            ],
            verification=[
                {"question": "Can these capability surfaces be exercised together from an entry point or external input?",
                 "method": "static-source", "reason": "Capability combinations matter only when the surfaces can compose."},
            ],
            response={"summary": control, "actions": ["Prove reachability between surfaces", "Add least-privilege controls"]},
            composition=comp,
            attenuators=["Component-level composition; inter-surface reachability is not proven by this rule."],
        ))

    if "CAP-NET" in ids and "CAP-CRED" in ids:
        combo("CR-EXFIL", "Exfiltration-capable", "This component can read credential material and send data off-host.",
              "high", ["CAP-CRED", "CAP-NET"], "Constrain credential scope and network egress.")
    elif "CAP-NET" in ids and "CAP-FS-READ" in ids:
        combo("CR-EXFIL", "Exfiltration-capable", "This component can read files or enumerate sensitive data and send data off-host.",
              "medium", ["CAP-FS-READ", "CAP-NET"], "Constrain readable paths and network egress.")
    if "CAP-NET" in ids and "CAP-EXEC" in ids:
        combo("CR-RCE", "Remote-execution-capable", "This component combines network reach with command/process execution.",
              "critical", ["CAP-NET", "CAP-EXEC"], "Separate network inputs from execution sinks.")
    elif "CAP-NET" in ids and "CAP-DYNLOAD" in ids:
        combo("CR-RCE", "Remote-execution-capable", "This component combines network reach with dynamic code loading.",
              "critical", ["CAP-NET", "CAP-DYNLOAD"], "Pin loadable code and isolate network inputs.")
    if "CAP-FS-WRITE" in ids and "CAP-EXEC" in ids:
        combo("CR-SELFMOD", "Self-modifying-capable", "This component can write files and execute commands or processes.",
              "high", ["CAP-FS-WRITE", "CAP-EXEC"], "Keep writable paths disjoint from executable paths.")
    elif "CAP-FS-WRITE" in ids and "CAP-DYNLOAD" in ids:
        combo("CR-SELFMOD", "Self-modifying-capable", "This component can write files and dynamically load code.",
              "high", ["CAP-FS-WRITE", "CAP-DYNLOAD"], "Keep writable paths disjoint from loadable paths.")
    for active in ("CAP-EXEC", "CAP-DYNLOAD", "CAP-NET", "CAP-FS-WRITE"):
        if "CAP-INSTALL" in ids and active in ids:
            combo("CR-INSTALL-AUTH", "Install-time authority", "Install/build-time code can exercise active capability before explicit use.",
                  "high", ["CAP-INSTALL", active], "Disable install scripts or make them deterministic and offline.")
            break
    for active in ("CAP-EXEC", "CAP-DYNLOAD", "CAP-NET", "CAP-CRED"):
        if "CAP-AGENT" in ids and active in ids:
            combo("CR-AGENT-RISK", "Agentic blast-radius capable",
                  "Agent-directed content is co-located with high-reach capability.",
                  "high", ["CAP-AGENT", active], "Separate agent-ingested content from high-reach actions.")
            break

    top = max(present, key=lambda c: _SEV_RANK[c[2]])[2]
    if len(amps) >= 2 and top == "high":
        top = "critical"
    surfaces = ", ".join(c[1] for c in present)
    n += 1
    findings.append(_finding(
        f"cap-{n}", "capability", "Capability profile (blast radius)",
        f"This component exposes {len(present)} capability surface(s): {surfaces}. "
        f"Overall blast radius if compromised or confused: {top}.",
        top, max(c[3] for c in present), [c[4][0] for c in present],
        disproof=[
            "The surfaces are in unreachable code.",
            "Capabilities are already isolated (sandbox, dropped privileges, egress controls).",
        ],
        verification=[
            {"question": "Which capabilities are actually reachable, and are any already bounded by sandbox/permissions?",
             "method": "static-source", "reason": "Blast radius is the reachable, unbounded subset."},
        ],
        response={"summary": "Reduce to least capability: remove unused surfaces, isolate the rest.",
                  "actions": ["Remove unused capability surfaces", "Sandbox / drop privileges",
                              "Add egress + filesystem + dynamic-load allowlists",
                              "Move risky surfaces behind explicit approval"]},
        composition="CR-PROFILE",
        amplifiers=amps or None,
    ))
    return findings


# --------------------------------------------------------------------------
# Agentic-risk lens: a COMPOSITE PROFILE, not new ontology. Pulls
# together capability (affordances), AITM (manipulation surface), and dispatch
# decisions to answer: "what can this agent / tool / MCP server be tricked into
# doing?" Constructive framing: it maps a (possibly trusted) tool's
# manipulation + blast-radius surface; it is not a maliciousness verdict.
# --------------------------------------------------------------------------

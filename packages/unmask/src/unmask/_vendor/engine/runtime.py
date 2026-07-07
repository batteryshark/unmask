"""Runtime verification contract.

The scanner is intentionally static. This module describes the runtime checks a
reviewer may approve later; it never executes target code, opens sockets, or
captures traffic.
"""

from __future__ import annotations

RUNTIME_NOTE = (
    "Runtime verification was not run. Parallax scan/assess is static by default; "
    "sandbox execution, branch exploration, and network capture require explicit "
    "operator approval and an isolated environment."
)

_TASKS = [
    {
        "id": "sandbox-execution",
        "method": "dynamic",
        "description": "Execute selected code paths only inside an isolated sandbox or VM.",
        "requiresIsolation": True,
    },
    {
        "id": "branch-exploration",
        "method": "dynamic",
        "description": "Exercise time, environment, feature-flag, or dormant branches under controlled conditions.",
        "requiresIsolation": True,
    },
    {
        "id": "network-capture",
        "method": "network",
        "description": "Capture egress, proxy, DNS, or TLS behavior in an isolated network.",
        "requiresIsolation": True,
    },
]

_BRANCH_WORDS = ("branch", "gated", "gate", "time", "environment", "dormant", "condition")


def _finding_refs(findings, method):
    refs = []
    for f in findings or []:
        for v in f.get("verification", []) or []:
            if (v.get("method") or "").lower() != method:
                continue
            refs.append({
                "findingId": f.get("id"),
                "composition": f.get("composition"),
                "question": v.get("question"),
            })
    return refs


def _branch_refs(findings):
    refs = []
    for f in findings or []:
        for v in f.get("verification", []) or []:
            if (v.get("method") or "").lower() != "dynamic":
                continue
            text = " ".join([v.get("question") or "", v.get("reason") or ""]).lower()
            if any(w in text for w in _BRANCH_WORDS):
                refs.append({
                    "findingId": f.get("id"),
                    "composition": f.get("composition"),
                    "question": v.get("question"),
                })
    return refs


def build_status(findings=None) -> dict:
    """Return a machine-readable "planned but not run" runtime status."""
    dyn_refs = _finding_refs(findings, "dynamic")
    net_refs = _finding_refs(findings, "network")
    branch_refs = _branch_refs(findings)
    triggered = {
        "sandbox-execution": dyn_refs,
        "branch-exploration": branch_refs,
        "network-capture": net_refs,
    }
    tasks = []
    for t in _TASKS:
        tasks.append({
            "id": t["id"],
            "method": t["method"],
            "status": "not-run",
            "approvalRequired": True,
            "executedUntrustedCode": False,
            "requiresIsolation": t["requiresIsolation"],
            "description": t["description"],
            "triggeredBy": triggered[t["id"]],
        })
    requested = sorted({r["composition"] for refs in triggered.values()
                        for r in refs if r.get("composition")})
    return {
        "status": "not-run",
        "approvalRequired": True,
        "executedUntrustedCode": False,
        "policy": RUNTIME_NOTE,
        "requestedByCompositions": requested,
        "tasks": tasks,
    }


def coverage_note() -> str:
    return RUNTIME_NOTE

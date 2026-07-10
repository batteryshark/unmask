"""Readiness check behind `unmask tools doctor`.

Answers the three questions a newcomer has right after cloning:
  1. Is the RE add-on (`unmask-re`) installed, and what can it do?
  2. Which external tools (jadx, ilspycmd, node, …) resolved, and how do I get the
     missing ones?  Missing tools are OPTIONAL — each only gates a specific binary type.
  3. Is an agentic-review model configured (for `--review`), or is it unset?

`readiness_report()` returns a JSON-able dict so `setup.sh` can consume it (offer to
install the missing tools); `render_readiness()` is the human view.
"""

from __future__ import annotations


def _review_model_status() -> dict:
    """Whether the review overlay has a model configured — resolved from env/.env WITHOUT
    building the model or leaking the key. Pure config, so it's safe even without the
    `review` extra installed."""
    from unmask.reviewers.config import ReviewModelConfig
    try:
        cfg = ReviewModelConfig.from_env()
    except Exception as exc:  # no model set → ReviewConfigError; treat as "not configured"
        return {"configured": False, "reason": str(exc)}
    return {"configured": True, "provider": cfg.provider, "model": cfg.model,
            "baseUrl": cfg.base_url, "kind": getattr(cfg, "kind", None),
            "hasApiKey": bool(getattr(cfg, "api_key", None))}


def readiness_report() -> dict:
    """Assemble the full readiness picture: RE providers, their external-tool
    prerequisites (duck-typed off each loaded provider), and review-model config."""
    from unmask.providers import discover_providers
    status = discover_providers()
    rep = status.to_report()

    tools: dict[str, dict] = {}
    for p in status.providers:
        fn = getattr(p.instance, "prerequisites_status", None)
        if not callable(fn):
            continue
        try:
            entries = fn()
        except Exception:
            continue
        for t in entries:
            cur = tools.get(t["tool"])
            if cur is None:
                tools[t["tool"]] = dict(t)
            else:  # same tool needed by >1 provider: present only if all agree, union needers
                cur["present"] = bool(cur["present"] and t.get("present"))
                cur["neededBy"] = list(cur.get("neededBy") or []) + list(t.get("neededBy") or [])
    rep["externalTools"] = sorted(tools.values(), key=lambda t: (t["present"], t["tool"]))
    rep["reviewModel"] = _review_model_status()
    return rep


def render_readiness(rep: dict) -> str:
    lines = ["unmask readiness", "----------------"]

    lines.append(f"RE providers: {'installed' if rep['reProvidersInstalled'] else 'NOT installed'}")
    for p in rep.get("providers") or []:
        mark = "!" if p["error"] else "+"
        caps = ", ".join(p["capabilities"]) or "(no caps)"
        lines.append(f"  [{mark}] {p['id']}: {caps}" + (f"  ERROR: {p['error']}" if p["error"] else ""))
    if not rep.get("providers"):
        lines.append("  (none registered)")

    tools = rep.get("externalTools") or []
    if tools:
        lines.append("")
        lines.append("External tools (missing ones are optional — each gates one binary type):")
        for t in tools:
            mark = "+" if t["present"] else "-"
            head = f"  [{mark}] {t['tool']:10} {'present' if t['present'] else 'missing'}"
            if not t["present"]:
                head += f"  (needed by: {', '.join(t.get('neededBy') or [])})"
            lines.append(head)
            if not t["present"] and t.get("hint"):
                lines.append(f"        -> {t['hint']}")

    rm = rep.get("reviewModel") or {}
    lines.append("")
    if rm.get("configured"):
        key = "key set" if rm.get("hasApiKey") else "no key"
        lines.append(f"Review model: configured — {rm.get('provider')} · {rm.get('model')} "
                     f"({rm.get('baseUrl')}, {key})")
    else:
        lines.append("Review model: not configured (only needed for `unmask run --review`).")
        lines.append("        -> set UNMASK_REVIEW_* in .env — copy .env.example to start")

    if rep.get("hint"):
        lines.append("")
        lines.append(rep["hint"])
    return "\n".join(lines)

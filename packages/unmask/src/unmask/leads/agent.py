"""The bounded lead proposer (pydantic-ai).

Residue in, a typed `LeadBatch` out. The model proposes WHERE to look and WHICH known
investigation to run (`transform`/`dataflow`/`human`) on the residue it is shown — it
never judges maliciousness and never targets anything outside the residue. An empty
batch is a valid answer and is how loop-until-dry terminates. Any failure degrades to no
leads (the residue is still surfaced as a coverage note by the caller) — never a claim.
"""

from __future__ import annotations

from unmask.leads.schemas import Lead, LeadBatch

LEAD_INSTRUCTIONS = (
    "You are a malware-triage investigator planning follow-ups. You are given RESIDUE: "
    "files that produced static-analysis signal (atoms across ≥2 capability families) but "
    "did NOT compose into any finding — 'weird but uncaught'. Propose bounded leads.\n\n"
    "Rules:\n"
    "- You propose WHERE to look and WHICH action to run; you do NOT decide whether "
    "anything is malicious. The deterministic engine executes your lead and judges the "
    "result.\n"
    "- `target` MUST be one of the residue paths shown. Do not invent targets.\n"
    "- kind: `transform` (open the artifact up — deobfuscate/decompile/unpack — when it "
    "looks packed/obfuscated/binary), `dataflow` (re-check taint when payload steps "
    "co-occur in one file), `human` (genuinely needs a person; can't be acted on "
    "mechanically).\n"
    "- Be selective: a lead per residue item only if the co-occurrence is actually "
    "suspicious. If nothing warrants a lead, return an EMPTY list. Do not pad.\n"
    "- One short rationale per lead, grounded in the atoms shown."
)


def build_lead_proposer(model=None):
    """An Agent that emits a validated LeadBatch. `model` may be a pydantic-ai model
    (incl. TestModel for tests); default resolves one from the environment."""
    from pydantic_ai import Agent

    if model is None:
        from unmask.reviewers.config import ReviewModelConfig
        model = ReviewModelConfig.from_env().build_model()
    return Agent(model, output_type=LeadBatch, instructions=LEAD_INSTRUCTIONS, retries=2)


def _build_prompt(residue: list[dict]) -> str:
    lines = ["Residue (path — families — atoms):"]
    for r in residue:
        lines.append(f"- {r['path']}  —  {', '.join(r['families'])}  —  {', '.join(r['atoms'])}")
    lines += ["", "Propose leads (empty list if none warrant one). target must be a path above."]
    return "\n".join(lines)


def propose_leads(residue: list[dict], *, agent=None, model=None) -> list[Lead]:
    """Return the model's proposed leads for this residue, filtered to valid targets.
    Never raises — a failure yields no leads (residue stays surfaced by the caller)."""
    if not residue:
        return []
    agent = agent or build_lead_proposer(model)
    valid = {r["path"] for r in residue}
    try:
        batch: LeadBatch = agent.run_sync(_build_prompt(residue)).output
    except Exception:
        return []
    return [ld for ld in batch.leads if ld.target in valid]

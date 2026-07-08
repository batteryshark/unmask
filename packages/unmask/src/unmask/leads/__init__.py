"""Adaptive investigation leads: bounded model-proposed follow-ups on residue.

The model steers WHERE to look (which residue, which known action); the deterministic
engine executes the lead and judges the result. Leads only ever ADD coverage — a lead
becomes a real finding, a cleared note, or an explicit tracked human lead, never a
softened verdict. Off unless `config.leads`; needs a review model.
"""

from __future__ import annotations

from unmask.leads.agent import build_lead_proposer, propose_leads
from unmask.leads.residue import gather_residue
from unmask.leads.schemas import Lead, LeadBatch, LeadKind, LeadResolution

__all__ = [
    "Lead", "LeadBatch", "LeadKind", "LeadResolution",
    "gather_residue", "propose_leads", "build_lead_proposer",
]

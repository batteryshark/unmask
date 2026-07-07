"""Post-report QA — advisory rule-tuning feedback (unmask[review]).

After review, cluster the findings that were knocked down (deescalated / refuted /
suppressed) and suggest where a rule fires too permissively. Advisory only: it
never mutates rules, packs, taxonomy, or findings, and every suggestion names its
false-negative risk. Clearly engineering feedback, separate from the target's
disposition.
"""

from __future__ import annotations

from unmask.qa.agent import build_qa_agent, suggest_rule_tunings
from unmask.qa.cluster import cluster_noise, knocked_down
from unmask.qa.schemas import RuleTuningSuggestion

__all__ = [
    "suggest_rule_tunings", "build_qa_agent", "cluster_noise", "knocked_down",
    "RuleTuningSuggestion",
]

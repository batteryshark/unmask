"""The post-report rule-tuning QA agent.

Given the report and the review judgments, it looks for rules that fire too
permissively — clusters of the SAME shape that review keeps knocking down — and
proposes advisory tweaks. It never mutates anything, always cites concrete
findings, and always names the false-negative risk of acting on a suggestion.
Reuses the review model config (any OpenAI-compatible endpoint).
"""

from __future__ import annotations

from unmask.qa.cluster import cluster_noise
from unmask.qa.schemas import RuleTuningSuggestion

QA_INSTRUCTIONS = (
    "You are a detection-engineering analyst reviewing the QUALITY of malicious-code "
    "rules, not the target. You are given clusters of findings that a reviewer already "
    "knocked down (deescalated / refuted / suppressed), grouped by shape. Suggest "
    "rule-tuning changes only where a cluster shows a rule firing too permissively or "
    "too noisily.\n\n"
    "Rules:\n"
    "- Every suggestion MUST cite >=1 concrete finding id.\n"
    "- Prefer clusters (repeated same-shape noise) over one-offs.\n"
    "- ALWAYS state the false-negative risk (`risk`): what real malicious code could slip "
    "through if this change were applied.\n"
    "- NEVER suggest suppressing a high/critical-severity composition just because it is common.\n"
    "- Missing decompiler / missing fetch / missing dynamic evidence is a COVERAGE gap, not "
    "noise — do not propose tuning it away.\n"
    "- You are advisory. You do not change rules, packs, taxonomy, or the findings.\n"
    "Return zero or more RuleTuningSuggestion. Returning none is correct when the "
    "suppressions look like genuine one-offs rather than a rule problem."
)


def build_qa_agent(model=None):
    from pydantic_ai import Agent

    if model is None:
        from unmask.reviewers.config import ReviewModelConfig
        model = ReviewModelConfig.from_env().build_model()
    return Agent(model, output_type=list[RuleTuningSuggestion], instructions=QA_INSTRUCTIONS, retries=2)


def _cluster_prompt(assessment: dict, clusters: list[dict]) -> str:
    findings_by_id = {f.get("id"): f for f in assessment.get("findings", [])}
    lines = ["Findings knocked down by review, clustered by shape:"]
    for i, c in enumerate(clusters, 1):
        lines.append(f"\nCluster {i}: composition={c['composition']} rules={c['rule_ids']} "
                     f"atoms={c['atoms']} size={c['size']} verdicts={c['verdicts']}")
        for fid in c["finding_ids"]:
            f = findings_by_id.get(fid, {})
            lines.append(f"  - {fid}: {f.get('title')} — {(f.get('claim') or '')[:160]}")
    lines.append("\nSuggest rule tunings only where a cluster shows an over-permissive rule; "
                 "cite finding ids and state the false-negative risk for each.")
    return "\n".join(lines)


def suggest_rule_tunings(assessment: dict, judgments, *, model=None, agent=None,
                         min_cluster_size: int = 2) -> list[RuleTuningSuggestion]:
    clusters = [c for c in cluster_noise(assessment, judgments) if c["size"] >= min_cluster_size]
    if not clusters:
        return []
    agent = agent or build_qa_agent(model)
    try:
        result = agent.run_sync(_cluster_prompt(assessment, clusters))
        return list(result.output)
    except Exception as exc:  # QA is advisory; failure yields a human-review flag, never a crash
        fids = [fid for c in clusters for fid in c["finding_ids"]][:10] or ["?"]
        return [RuleTuningSuggestion(
            kind="needs-human-rule-review", finding_ids=fids,
            suggestion="Automated rule-tuning QA was unavailable; a human should review the "
                       "clustered suppressions for a possibly over-permissive rule.",
            rationale=f"QA model error: {exc!r}",
            risk="None — advisory only; no automated change was made.")]

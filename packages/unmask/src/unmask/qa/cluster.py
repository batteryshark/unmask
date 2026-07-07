"""Deterministic pre-pass: find repeated noise and cluster it.

Only findings that REVIEW knocked down — deescalate / refute / suppress — are
noise signals (a confirmed/escalated finding is not a rule problem). Cluster them
by (composition, cited rule ids), because a rule that is too permissive tends to
produce the SAME wrong shape repeatedly. Singleton suppressions are usually
one-off, not a rule to tune. No model here; this just decides what to ask about.
"""

from __future__ import annotations

_NOISE_VERDICTS = {"deescalate", "refute", "suppress"}


def _verdict(j):
    return j.verdict if hasattr(j, "verdict") else j.get("verdict")


def _finding_id(j):
    return j.finding_id if hasattr(j, "finding_id") else j.get("finding_id")


def knocked_down(assessment: dict, judgments) -> list[tuple[dict, str]]:
    """(finding, verdict) for findings review deescalated/refuted/suppressed."""
    by_verdict = {}
    for j in judgments:
        v = _verdict(j)
        if v in _NOISE_VERDICTS:
            by_verdict[_finding_id(j)] = v
    findings_by_id = {f.get("id"): f for f in assessment.get("findings", [])}
    return [(findings_by_id[fid], v) for fid, v in by_verdict.items() if fid in findings_by_id]


def cluster_noise(assessment: dict, judgments) -> list[dict]:
    """Group knocked-down findings by (composition, cited rule ids). Returns clusters
    sorted largest-first; `size` is the member count (>=2 = a tuning candidate)."""
    obs_by_id = {o.get("id"): o for o in assessment.get("observations", [])}
    groups: dict[tuple, dict] = {}
    for finding, verdict in knocked_down(assessment, judgments):
        comp = finding.get("composition")
        rules, atoms = set(), set()
        for oid in finding.get("evidence", []):
            o = obs_by_id.get(oid)
            if not o:
                continue
            if o.get("rule_id"):
                rules.add(o["rule_id"])
            if o.get("atom"):
                atoms.add(str(o["atom"]).split(".")[0])
        key = (comp, tuple(sorted(rules)))
        g = groups.setdefault(key, {"composition": comp, "rule_ids": set(), "atoms": set(),
                                    "finding_ids": [], "verdicts": []})
        g["rule_ids"] |= rules
        g["atoms"] |= atoms
        g["finding_ids"].append(finding.get("id"))
        g["verdicts"].append(verdict)

    clusters = [{"composition": g["composition"], "rule_ids": sorted(g["rule_ids"]),
                 "atoms": sorted(g["atoms"]), "finding_ids": g["finding_ids"],
                 "verdicts": g["verdicts"], "size": len(g["finding_ids"])}
                for g in groups.values()]
    clusters.sort(key=lambda c: -c["size"])
    return clusters

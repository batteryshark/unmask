"""Correlation: group findings that share a file or network indicator into one
cross-signal cluster. Ported from `mcd_lens.assess.correlate`.

Co-location is corroborating CONTEXT, never a silent confidence change: each
finding keeps its own confidence; the cluster states the rule and what breaks it.
"""

from __future__ import annotations

from unmask.scanner.assess.common import (
    _COOCCUR_INSIGHTS, _finding_loci, _rank, _signal_type,
)


def _narrative(n_members, comps, shared_files, shared_inds):
    if shared_files:
        where = "in " + ", ".join(f"`{p}`" for p in shared_files[:3])
    elif shared_inds:
        where = "around " + ", ".join(shared_inds[:3])
    else:
        where = "in the same component"
    return f"{n_members} malicious-code findings co-occur {where}: {', '.join(sorted(set(comps)))}."


def _insights(comps):
    cset = set(comps)
    return [text for keys, text in _COOCCUR_INSIGHTS if keys <= cset]


def _cluster_disproof(shared_files, shared_inds):
    out = []
    if shared_files:
        out.append("The findings sit in the same file but are not actually connected in control "
                   "or data flow (co-location only); a reachability check that finds no path "
                   "breaks the link.")
    if shared_inds:
        out.append("The shared network indicator is a benign, documented endpoint rather than "
                   "attacker-controlled.")
    out.append("Each member finding's own disproof criteria still apply; disprove the members and "
               "the correlation dissolves.")
    return out


def _correlate(findings, obs_by_id):
    n = len(findings)
    loci = [_finding_loci(f, obs_by_id) for f in findings]
    parent = list(range(n))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for i in range(n):
        for j in range(i + 1, n):
            if (loci[i][0] & loci[j][0]) or (loci[i][1] & loci[j][1]):
                parent[find(i)] = find(j)

    groups = {}
    for i in range(n):
        groups.setdefault(find(i), []).append(i)

    correlations = []
    for members in groups.values():
        if len(members) < 2:
            continue
        mf = [findings[i] for i in members]
        file_counts, ind_counts = {}, {}
        sig, evidence, seen = set(), [], set()
        for i in members:
            for p in loci[i][0]:
                file_counts[p] = file_counts.get(p, 0) + 1
            for x in loci[i][1]:
                ind_counts[x] = ind_counts.get(x, 0) + 1
            for oid in findings[i].get("evidence", []):
                o = obs_by_id.get(oid)
                if not o:
                    continue
                sig.add(_signal_type(o))
                if oid not in seen:
                    seen.add(oid)
                    evidence.append(oid)
        shared_files = sorted(p for p, c in file_counts.items() if c >= 2)
        shared_inds = sorted(x for x, c in ind_counts.items() if c >= 2)
        comps = sorted({f.get("composition") for f in mf if f.get("composition")})
        sev = max((f.get("severity") for f in mf), key=_rank)
        correlations.append({
            "id": "",
            "memberFindingIds": [f["id"] for f in mf],
            "compositions": comps,
            "signalTypes": sorted(sig),
            "crossSignal": len(sig) >= 2,
            "sharedFiles": shared_files,
            "sharedIndicators": shared_inds,
            "severity": sev,
            "evidence": evidence,
            "narrative": _narrative(len(mf), comps, shared_files, shared_inds),
            "insights": _insights(comps),
            "corroboration": (
                f"{len(sig)} signal type(s) ({', '.join(sorted(sig))}) co-located. "
                "Co-location across independent signals is corroborating context; it does NOT "
                "alter any individual finding's confidence. A disposition may weigh it through "
                "an explicit, stated rule."),
            "disproof": _cluster_disproof(shared_files, shared_inds),
        })
    correlations.sort(key=lambda c: (-_rank(c["severity"]), -len(c["memberFindingIds"])))
    for k, c in enumerate(correlations, 1):
        c["id"] = f"corr-{k}"
    return correlations

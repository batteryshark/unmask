"""Correlation: group findings that share a file or network indicator into one
cross-signal cluster, with a stated reason and a disproof."""

from __future__ import annotations

from .common import *  # noqa: F401,F403

def _narrative(n_members, comps, shared_files, shared_inds):
    if shared_files:
        where = "in " + ", ".join(f"`{p}`" for p in shared_files[:3])
    elif shared_inds:
        where = "around " + ", ".join(shared_inds[:3])
    else:
        where = "in the same component"
    return f"{n_members} malicious-code findings co-occur {where}: {', '.join(sorted(set(comps)))}."


def _insights(comps):
    """The stated meaning of each composition combination present in the cluster."""
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
    """Group findings that share a file or a network indicator into one narrative.

    Co-location is read as corroborating CONTEXT, never as a silent confidence
    change: each finding keeps its own confidence, and the cluster states the rule
    plus what would break the link. Proving an actual control/data-flow connection
    is the reachability phase, not this one.
    """
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


# --- Disposition: a deterministic next-action recommendation. ----------
# severity (how bad if real) and confidence (how sure) are weighed together by an
# EXPLICIT rule, never collapsed into one score and never set by a model.

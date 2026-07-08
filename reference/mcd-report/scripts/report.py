#!/usr/bin/env python3
"""Wrapper that runs the MCD pipeline and writes the assessment report.

Usage: report.py <target> <out_dir> [adjudications.json]

Pipeline (all deterministic; no LLM, no network):

    engine.observe(target)          -> (observations, inv)
    mcd_reading(observations, inv)  -> mcd findings
    engine.report.build(...)        -> scan-report dict
    mcd_lens.build_assessment(...)  -> assessment dict
    render_html / render_markdown / to_json  -> report.{html,md,json}

If an ``adjudications.json`` is passed and exists, it is treated as an agentic
review overlay: `build_adjudication` folds the reviewer's per-finding verdicts and
confidences over the deterministic scan and attaches an `adjudication` block that
`render.py` surfaces as the "Adjudication (agentic review)" section. The engine
still owns the deterministic disposition; the overlay adds a *reviewed* one.

``import engine`` / ``import mcd_lens`` resolve to the shared repo-root packages;
``run.sh`` puts the parallax-goalpacks repo root on ``PYTHONPATH``. As a fallback
(running this script directly), we add the repo root ourselves.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def _ensure_imports() -> None:
    """Make ``import engine`` / ``import mcd_lens`` resolve to the repo-root packages.

    Layout: parallax-goalpacks/skills/mcd-report/scripts/report.py
    Repo root is three parents up from this file's dir.
    """
    try:
        import engine  # noqa: F401
        import mcd_lens  # noqa: F401
        return
    except ImportError:
        pass
    repo_root = Path(__file__).resolve().parents[3]
    if (repo_root / "engine" / "__init__.py").is_file():
        sys.path.insert(0, str(repo_root))


# --- Adjudication overlay: reviewer verdicts folded over the scan. ------------

# Response tiers, from close-out to immediate action. The reviewer picks a
# responseTier per finding; the overlay's responseLevel is the max across the
# findings that count toward disposition.
_RESPONSE_TIERS = {
    0: ("close", "No action: the finding is closed out."),
    1: ("document", "Document the finding and move on; no engineering change needed."),
    2: ("engineering-referral", "Refer to engineering for a fix or a design change."),
    3: ("passive-monitoring", "Keep the artifact under passive monitoring."),
    4: ("active-monitoring", "Put the artifact under active monitoring and review."),
    5: ("immediate", "Immediate action: hold, isolate, or remediate now."),
}

# Reviewed confidence at or above this, with a confirm/escalate verdict, is enough
# to recommend quarantine. Mirrors the engine's _QUARANTINE_MIN_CONF spirit, but
# keyed off the reviewer's confidence rather than engine severity (which the
# overlay does not re-derive).
_REVIEWED_QUARANTINE_MIN_CONF = 0.65

# Verdicts that leave a finding "standing" (still a live malicious-code shape) vs
# knocked down. confirm/escalate/deescalate keep the finding in the disposition;
# refute/suppress remove it.
_STANDING_VERDICTS = {"confirm", "escalate", "deescalate"}
_QUARANTINE_VERDICTS = {"confirm", "escalate"}


def _reviewed_disposition(standing: list[dict]) -> dict:
    """Recompute disposition over the reviewed confidences of the non-excluded
    findings. Deliberately simple and stated (the engine owns the authoritative,
    severity-aware disposition; this is the reviewer's overlay):

    - quarantine if any non-excluded finding has reviewedConfidence >= 0.65 AND a
      confirm/escalate verdict (the reviewer both raised suspicion and is sure);
    - else review if any confirm/escalate/deescalate finding remains (a live shape
      an engineer should still resolve);
    - else clear (the review knocked everything down).
    """
    quarantine = [f for f in standing
                  if f.get("verdict") in _QUARANTINE_VERDICTS
                  and (f.get("reviewedConfidence") or 0) >= _REVIEWED_QUARANTINE_MIN_CONF]
    if quarantine:
        return {
            "recommendation": "quarantine",
            "rationale": (f"Recommend quarantine after review: {len(quarantine)} finding(s) confirmed or "
                          f"escalated at reviewed confidence >= {_REVIEWED_QUARANTINE_MIN_CONF}. Hold the "
                          "artifact until the verification questions are answered."),
        }
    live = [f for f in standing if f.get("verdict") in _STANDING_VERDICTS]
    if live:
        return {
            "recommendation": "review",
            "rationale": (f"Recommend review after review: {len(live)} malicious-code finding(s) survived "
                          "the review (confirmed, escalated, or de-escalated) but do not meet the "
                          "quarantine bar. Have an engineer resolve them before relying on the code."),
        }
    return {
        "recommendation": "clear",
        "rationale": ("Clear after review: the reviewer refuted or suppressed every finding that would "
                      "count toward disposition. This is 'clear of standing mcd findings', not a full "
                      "safety guarantee."),
    }


def build_adjudication(adjudications: dict, assessment: dict) -> dict | None:
    """Fold an agentic-review overlay over the deterministic assessment.

    `adjudications` carries a `reviewer` block and a list of per-finding verdicts:
    the engine found the shapes; the reviewer read the code behind each and set a
    verdict, confidence, and response tier. Returns an `adjudication` dict shaped
    for render.py's `_adjudication_html` / `_reviewed_executive_summary`, or None
    when there are no findings to adjudicate.
    """
    findings = adjudications.get("findings") or []
    if not findings:
        return None

    counts = {k: 0 for k in ("confirm", "escalate", "deescalate", "refute", "suppress")}
    unreviewed = 0
    moved = []
    for f in findings:
        verdict = f.get("verdict")
        if verdict in counts:
            counts[verdict] += 1
        else:
            unreviewed += 1
        eng_conf = f.get("engineConfidence")
        rev_conf = f.get("reviewedConfidence")
        if rev_conf is not None and eng_conf is not None and rev_conf != eng_conf:
            moved.append({
                "findingId": f.get("id"),
                "decision": verdict,
                "originalConfidence": eng_conf,
                "reviewedConfidence": rev_conf,
            })
    if unreviewed:
        counts["unreviewed"] = unreviewed

    # Non-excluded findings drive both the response level and the reviewed
    # disposition. excludedFromDisposition lets the reviewer read a finding but keep
    # it out of the recommendation (e.g. a refuted false positive).
    non_excluded = [f for f in findings if not f.get("excludedFromDisposition")]

    tiers = [f.get("responseTier") for f in non_excluded
             if isinstance(f.get("responseTier"), int)]
    if tiers:
        top = max(tiers)
        name, summary = _RESPONSE_TIERS.get(top, ("unknown", "Unrecognized response tier."))
        response_level = {"tier": top, "name": name, "summary": summary}
    else:
        response_level = None

    reviewed = _reviewed_disposition(non_excluded)
    engine_disposition = (assessment.get("disposition") or {}).get("recommendation")

    return {
        "note": ("Agentic review overlaid on the deterministic scan: the engine found the shapes; the "
                 "reviewer read the code behind each and set verdicts and confidence."),
        "reviewer": adjudications.get("reviewer"),
        "counts": counts,
        "moved": moved,
        "responseLevel": response_level,
        "reviewedDisposition": reviewed,
        "engineDisposition": engine_disposition,
        "dispositionChanged": reviewed["recommendation"] != engine_disposition,
    }


def main(argv: list[str]) -> int:
    if len(argv) not in (3, 4):
        print("usage: report.py <target> <out_dir> [adjudications.json]", file=sys.stderr)
        return 2

    target = argv[1]
    out_dir = Path(argv[2])
    out_dir.mkdir(parents=True, exist_ok=True)
    adj_path = Path(argv[3]) if len(argv) == 4 else None

    _ensure_imports()
    from engine import engine as eng, report as report_mod, rules
    from mcd_lens import (
        mcd_reading, build_assessment, render_html, render_markdown, to_json,
    )

    started = datetime.now(timezone.utc).isoformat()
    observations, inv = eng.observe(target)
    findings = mcd_reading(observations, inv)
    report = report_mod.build(
        target, ["mcd"], inv, observations, findings, started, rules.ast_mode(),
    )
    assessment = build_assessment(report)

    if adj_path is not None and adj_path.is_file():
        adjudications = json.loads(adj_path.read_text(encoding="utf-8"))
        adjudication = build_adjudication(adjudications, assessment)
        if adjudication is not None:
            assessment["adjudication"] = adjudication

    (out_dir / "report.html").write_text(render_html(assessment), encoding="utf-8")
    (out_dir / "report.md").write_text(render_markdown(assessment), encoding="utf-8")
    (out_dir / "report.json").write_text(to_json(assessment), encoding="utf-8")

    summary = assessment.get("summary", {})
    disp = (assessment.get("disposition") or {}).get("recommendation", "?")
    reviewed = ""
    adj = assessment.get("adjudication")
    if adj:
        rd = (adj.get("reviewedDisposition") or {}).get("recommendation")
        reviewed = f", reviewed disposition {rd}"
    print(
        f"mcd-report: {summary.get('findingCount', 0)} mcd finding(s), "
        f"disposition {disp}{reviewed} -> {out_dir}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

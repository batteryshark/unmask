"""Phase nodes for the first build cut.

    InitializeRun -> InventoryTarget -> ScanAndCompose -> CoverageGate -> RenderReport -> Done

Faithful to docs/design.md's node responsibilities, collapsed where the first
cut doesn't yet branch (StaticScan + ComposeFindings run as one adapter call;
ExpandContainers / Decompile / ReviewBatch / NetworkFetch arrive in later
milestones as extra queued work the CoverageGate loops over).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from unmask.graph.runner import Done, GraphContext, Node
from unmask.inventory.tree import BINARY_KINDS, build_tree, classify_kind
from unmask.ledger.store import stable_key
from unmask.report.augment import augment_json_report, markdown_coverage_appendix
from unmask.scanner.native import NativeScanner


def _atomic_write(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


class InitializeRun(Node):
    def run(self, ctx: GraphContext) -> Node:
        d, s = ctx.deps, ctx.state
        _write_run_json(ctx, status="running")
        d.ledger.enqueue(
            run_id=s.run_id, key=stable_key(str(s.target_path), "inventory"),
            target=str(s.target_path), operation="inventory", category="discovery",
            title="Inventory target", priority=10,
        )
        d.ledger.event(s.run_id, "InitializeRun", "note",
                       {"projectId": s.project_id, "runId": s.run_id})
        return InventoryTarget()


class InventoryTarget(Node):
    def run(self, ctx: GraphContext) -> Node:
        d, s = ctx.deps, ctx.state
        cfg = d.config
        tree = build_tree(
            s.target_path, max_depth=cfg.tree_max_depth,
            max_entries=cfg.tree_max_entries, include_hidden=False,
        )
        d.paths.tree_dir.mkdir(parents=True, exist_ok=True)
        _atomic_write(d.paths.tree_dir / "target-tree.txt", tree.text)
        _atomic_write(d.paths.tree_dir / "target-tree.json", json.dumps(tree.json, indent=2))
        d.ledger.add_artifact(
            run_id=s.run_id, kind="target-tree", origin="inventory",
            path=str(d.paths.tree_dir / "target-tree.json"),
            logical_path="artifacts/tree/target-tree.json",
            metadata=tree.summary,
        )
        d.scratch["tree"] = tree

        # Binary artifacts: record them, then decide by the plugin boundary.
        has_re = d.toolchain.has_re
        for rel in tree.binary_paths:
            abspath = Path(s.target_path) / rel if Path(s.target_path).is_dir() else Path(s.target_path)
            kind = classify_kind(Path(rel))
            art_id = d.ledger.add_artifact(
                run_id=s.run_id, kind=kind if kind in BINARY_KINDS else "native-binary",
                origin="inventory", path=str(abspath), logical_path=rel,
            )
            wid = d.ledger.enqueue(
                run_id=s.run_id, key=stable_key(rel, "scan-binary"),
                target=rel, operation="scan-binary", category="binary",
                title=f"Deep-analyse binary artifact {rel}",
                payload={"artifactId": art_id, "kind": kind},
            )
            if not has_re:
                # Skill-layer blind spot: no RE provider at all.
                d.ledger.set_work_status(
                    wid, "blocked",
                    error="No RE provider installed (install unmask-re); binary not "
                          "deeply analysed. Reported as a coverage blind spot.",
                )
            else:
                # RE provider present but real decompilation is a later milestone;
                # be honest — defer, don't leave it silently queued forever.
                d.ledger.set_work_status(
                    wid, "deferred",
                    result={"note": "RE provider present; deep binary analysis is a "
                                    "pending milestone (stub provider). Artifact not "
                                    "yet decompiled."},
                )

        # Enqueue and immediately drive the source scan.
        d.ledger.enqueue(
            run_id=s.run_id, key=stable_key(str(s.target_path), "scan-source"),
            target=str(s.target_path), operation="scan-source", category="source",
            title="Static source scan (engine + mcd_lens)", priority=20,
        )
        # Close the inventory work item.
        _mark_op_done(ctx, "inventory")
        d.ledger.event(s.run_id, "InventoryTarget", "note",
                       {"binaryArtifacts": len(tree.binary_paths), "reInstalled": has_re})
        return ScanAndCompose()


class ScanAndCompose(Node):
    def run(self, ctx: GraphContext) -> Node:
        d, s = ctx.deps, ctx.state
        try:
            result = NativeScanner().scan(str(s.target_path))
        except Exception as exc:  # a broken target, not a missing scanner
            _fail_op(ctx, "scan-source", repr(exc))
            d.scratch["scanner_error"] = repr(exc)
            d.ledger.event(s.run_id, "ScanAndCompose", "error", {"error": repr(exc)})
            return CoverageGate()

        for o in result.observations:
            d.ledger.add_observation(
                run_id=s.run_id, obs_id=o.get("id"), atom=o.get("atom") or "UNKNOWN",
                confidence=o.get("confidence", 0.0), method=o.get("method", ""),
                rule_id=o.get("rule_id"), location=o.get("location"),
                evidence=o.get("evidence"), relationships=o.get("relationships"),
            )
        for f in result.findings:
            d.ledger.add_finding(
                run_id=s.run_id, finding_id=f.get("id"), lens=f.get("lens", "mcd"),
                composition=f.get("_composition"), title=f.get("title", "(untitled)"),
                claim=f.get("claim", ""), severity=f.get("severity", "info"),
                confidence=float(f.get("confidence", 0.0) or 0.0),
                confidence_label=f.get("confidenceLabel"),
                evidence=f.get("evidence"), disproof=f.get("disproof"),
                verification=f.get("verification"), response=f.get("response"),
                amplifiers=f.get("amplifiers"), attenuators=f.get("attenuators"),
            )
        d.scratch["scan"] = result
        _mark_op_done(ctx, "scan-source")
        d.ledger.event(s.run_id, "ScanAndCompose", "note",
                       {"observations": len(result.observations),
                        "findings": len(result.findings)})
        return ReviewFindings()


class ReviewFindings(Node):
    """Optional agentic adjudication. A reviewer reads each finding's evidence and
    the overlay recomputes a *reviewed* disposition (the model judges; the rule,
    not the model, sets disposition). Off unless config.review; a missing or failed
    model is an honest coverage note, never a hard stop. Judgments persist."""

    def run(self, ctx: GraphContext) -> Node:
        d, s = ctx.deps, ctx.state
        scan = d.scratch.get("scan")
        if not d.config.review or scan is None or not scan.findings:
            return CoverageGate()
        try:
            from unmask.reviewers import ReviewModelConfig, review_assessment
            model = d.review_model or ReviewModelConfig.from_env().build_model()
        except Exception as exc:
            d.ledger.event(s.run_id, "ReviewFindings", "note", {"skipped": repr(exc)})
            d.scratch["review_note"] = (
                "Agentic review was requested but no model is configured — install "
                f"unmask[review] and set UNMASK_REVIEW_* ({exc!r}).")
            return CoverageGate()

        assessment = scan.assessment
        reviews, overlay = review_assessment(assessment, model=model)
        d.scratch["reviews"] = reviews  # for post-report rule-tuning QA
        model_name = getattr(d.config, "model", None) or type(model).__name__
        for r in reviews:
            d.ledger.record_judgment(s.run_id, r, model=model_name)
        if overlay:
            assessment["adjudication"] = overlay
            from unmask.scanner.assess.render import render_html, render_json, render_markdown
            scan.rendered = {"html": render_html(assessment), "md": render_markdown(assessment),
                             "json": render_json(assessment)}
        d.ledger.event(s.run_id, "ReviewFindings", "note",
                       {"reviewed": len(reviews),
                        "reviewedDisposition": ((overlay or {}).get("reviewedDisposition") or {}).get("recommendation")})
        return CoverageGate()


class CoverageGate(Node):
    """Decide the next phase from ledger state, not model output."""

    def run(self, ctx: GraphContext) -> Node:
        d, s = ctx.deps, ctx.state
        actionable = d.ledger.actionable_count(s.run_id)
        d.ledger.event(s.run_id, "CoverageGate", "note",
                       {"actionable": actionable, "coverage": d.ledger.coverage(s.run_id)})
        # First cut has no re-queuing workers, so once source scan is terminal we
        # render. Later milestones loop back to a ProcessWorkQueue node here.
        return RenderReport()


class RenderReport(Node):
    def run(self, ctx: GraphContext) -> Done:
        d, s = ctx.deps, ctx.state
        coverage = d.ledger.coverage(s.run_id)
        scan = d.scratch.get("scan")
        tree = d.scratch.get("tree")
        counts = d.ledger.work_status_counts(s.run_id)

        sections = {
            "ledger": {
                "runId": s.run_id, "projectId": s.project_id,
                "runDir": str(s.run_dir), "dbSchemaVersion": "0.1.0",
                "coverage": coverage,
            },
            "sandbox": {"provider": d.config.sandbox, "networkMode": d.config.network,
                        "executedUntrustedCode": False, "dynamicExecution": "not-run"},
            "toolchain": {"profile": d.config.tool_profile, **d.toolchain.to_report()},
            "tree": (tree.json | {"textPath": "artifacts/tree/target-tree.txt",
                                  "jsonPath": "artifacts/tree/target-tree.json"}) if tree else {},
            "graph": {"iterations": s.iteration, "stoppedReason":
                      "completed" if scan else "scanner-unavailable"},
        }

        reports_dir = d.paths.reports_dir
        reports_dir.mkdir(parents=True, exist_ok=True)
        blocked_binaries = counts.get("blocked", 0)

        if scan is not None:
            _atomic_write(reports_dir / "report.html", scan.rendered["html"])
            md = scan.rendered["md"] + markdown_coverage_appendix(sections, blocked_binaries)
            _atomic_write(reports_dir / "report.md", md)
            report_json = augment_json_report(scan.rendered["json"], sections)
            disposition = (report_json.get("disposition") or {}).get("recommendation", "?")
            finding_count = (report_json.get("summary") or {}).get("findingCount",
                                                                    d.ledger.count_findings(s.run_id))
        else:  # scanner unavailable — honest, minimal report
            report_json = {
                "target": str(s.target_path),
                "error": d.scratch.get("scanner_error"),
                "summary": {"findingCount": 0},
                "disposition": {"recommendation": "unknown",
                                "rationale": "Static scanner unavailable; no reading produced."},
                **sections,
            }
            disposition = "unknown"
            finding_count = 0
            _atomic_write(reports_dir / "report.md",
                          f"# MCD report — scanner unavailable\n\n{d.scratch.get('scanner_error')}\n"
                          + markdown_coverage_appendix(sections, blocked_binaries))

        _atomic_write(reports_dir / "report.json", json.dumps(report_json, indent=2))
        for fmt, fname in (("html", "report.html"), ("md", "report.md"), ("json", "report.json")):
            fp = reports_dir / fname
            if fp.is_file():
                d.ledger.add_report(s.run_id, fmt, str(fp))

        # Post-report rule-tuning QA — advisory engineering feedback, only when the
        # findings were reviewed (it clusters what review knocked down).
        if scan is not None and d.config.post_report_qa != "off" and d.scratch.get("reviews"):
            _post_report_qa(ctx, scan.assessment, d.scratch["reviews"], reports_dir)

        status = "completed" if scan is not None else "partial"
        summary = {"disposition": disposition, "findingCount": finding_count,
                   "blockedBinaries": blocked_binaries}
        d.ledger.finish_run(s.run_id, status, coverage=coverage, summary=summary)
        _write_run_json(ctx, status=status, disposition=disposition)
        d.ledger.event(s.run_id, "RenderReport", "note", summary)

        return Done({
            "runId": s.run_id, "projectId": s.project_id, "runDir": str(s.run_dir),
            "status": status, "disposition": disposition, "findingCount": finding_count,
            "blockedBinaries": blocked_binaries,
            "reportPaths": {"html": str(reports_dir / "report.html"),
                            "md": str(reports_dir / "report.md"),
                            "json": str(reports_dir / "report.json")},
        })


# --- helpers ---------------------------------------------------------------

def _work_id_for_op(ctx: GraphContext, operation: str) -> str | None:
    row = ctx.deps.ledger.conn.execute(
        "select id from work_items where run_id=? and operation=? order by created_at limit 1",
        (ctx.state.run_id, operation)).fetchone()
    return row["id"] if row else None


def _mark_op_done(ctx: GraphContext, operation: str) -> None:
    wid = _work_id_for_op(ctx, operation)
    if wid:
        ctx.deps.ledger.set_work_status(wid, "done")


def _fail_op(ctx: GraphContext, operation: str, error: str) -> None:
    wid = _work_id_for_op(ctx, operation)
    if wid:
        ctx.deps.ledger.set_work_status(wid, "failed", error=error)


def _post_report_qa(ctx: GraphContext, assessment: dict, reviews, reports_dir) -> None:
    d, s = ctx.deps, ctx.state
    try:
        from unmask.qa import suggest_rule_tunings
        suggestions = suggest_rule_tunings(assessment, reviews, model=d.review_model)
    except Exception as exc:  # QA is advisory; never fail the run
        d.ledger.event(s.run_id, "PostReportQA", "note", {"error": repr(exc)})
        return
    _atomic_write(reports_dir / "qa.json", json.dumps({
        "kind": "rule-tuning-qa",
        "note": "Advisory engineering feedback on rule quality — NOT part of the target's "
                "disposition. Nothing here changes findings, rules, or taxonomy.",
        "suggestions": [x.model_dump() for x in suggestions],
    }, indent=2))
    _atomic_write(reports_dir / "qa.md", _qa_markdown(suggestions))
    for x in suggestions:
        d.ledger.record_qa_suggestion(s.run_id, x)
    d.ledger.add_report(s.run_id, "qa-json", str(reports_dir / "qa.json"))
    d.ledger.event(s.run_id, "PostReportQA", "note", {"suggestions": len(suggestions)})


def _qa_markdown(suggestions) -> str:
    lines = ["# Rule-tuning candidates (engineering feedback)", "",
             "_Advisory only — feedback for maintaining rule quality, not part of the target "
             "assessment. Nothing here changes findings, rules, or taxonomy._", ""]
    if not suggestions:
        lines += ["No rule-tuning candidates: the knocked-down findings did not cluster into a "
                  "repeated over-permissive shape.", ""]
        return "\n".join(lines)
    for x in suggestions:
        lines += [f"## {x.kind}",
                  f"- **Findings:** {', '.join(x.finding_ids)}"]
        if x.rule_ids:
            lines.append(f"- **Rules:** {', '.join(x.rule_ids)}")
        lines += [f"- **Suggestion:** {x.suggestion}",
                  f"- **Rationale:** {x.rationale}"]
        if x.estimated_noise_reduction:
            lines.append(f"- **Estimated noise reduction:** {x.estimated_noise_reduction}")
        lines += [f"- ⚠️ **False-negative risk:** {x.risk}", ""]
    return "\n".join(lines)


def _write_run_json(ctx: GraphContext, *, status: str, disposition: str | None = None) -> None:
    d, s = ctx.deps, ctx.state
    payload = {
        "runId": s.run_id, "projectId": s.project_id, "status": status,
        "dbPath": "run.db", "targetPath": str(s.target_path),
        "reportPaths": {"html": "reports/report.html", "markdown": "reports/report.md",
                        "json": "reports/report.json"},
    }
    if disposition is not None:
        payload["disposition"] = disposition
    _atomic_write(d.paths.run_json, json.dumps(payload, indent=2))

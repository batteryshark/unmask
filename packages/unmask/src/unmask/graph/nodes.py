"""Phase nodes, driven by pydantic-graph.

    InitializeRun -> InventoryTarget -> ScanAndCompose -> ReviewFindings
      -> CoverageGate -> RenderReport -> End

Each node is a `BaseNode` whose `run()` returns the next node (or `End`); the
`GraphBuilder` infers the edges from the return annotations. The graph controls
phases; the SQLite ledger — not the graph — is the coverage/resume oracle.

Node bodies are synchronous work (ledger, scanner, file I/O). The two agentic
steps call a reviewer that uses `run_sync`, which cannot run inside the graph's
event loop, so those calls are offloaded with `asyncio.to_thread`.
"""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass
from functools import partial
from pathlib import Path

from pydantic_graph import BaseNode, End, Graph, GraphBuilder, GraphRunContext

from unmask.graph.runner import MCDGraphDeps, MCDGraphState
from unmask.inventory.tree import BINARY_KINDS, build_tree, classify_kind
from unmask.ledger.store import stable_key
from unmask.report.augment import augment_json_report, markdown_coverage_appendix
from unmask.scanner.native import NativeScanner
from unmask.transform import (
    ArtifactRef, DerivedSource, TransformResult, fold_results, plan_transforms, run_transform_pass,
)

# Bound the reveal→rescan→re-plan fixpoint so a pathological provider (or a
# decompile that keeps producing new artifacts) can't loop forever.
_MAX_TRANSFORM_PASSES = 4
_MAX_TRANSFORMS = 64
# Runaway backstop for the ProcessWorkQueue loop (far above any real queue depth).
_MAX_WORK_ITEMS = 500

_Ctx = GraphRunContext[MCDGraphState, MCDGraphDeps]


def _atomic_write(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def _enter(ctx: _Ctx, name: str) -> None:
    ctx.state.iteration += 1
    ctx.deps.ledger.event(ctx.state.run_id, name, "enter")


@dataclass
class InitializeRun(BaseNode[MCDGraphState, MCDGraphDeps, dict]):
    async def run(self, ctx: _Ctx) -> "InventoryTarget":
        d, s = ctx.deps, ctx.state
        _enter(ctx, "InitializeRun")
        _write_run_json(ctx, status="running")
        d.ledger.enqueue(
            run_id=s.run_id, key=stable_key(str(s.target_path), "inventory"),
            target=str(s.target_path), operation="inventory", category="discovery",
            title="Inventory target", priority=10,
        )
        d.ledger.event(s.run_id, "InitializeRun", "note",
                       {"projectId": s.project_id, "runId": s.run_id})
        return InventoryTarget()


@dataclass
class InventoryTarget(BaseNode[MCDGraphState, MCDGraphDeps, dict]):
    async def run(self, ctx: _Ctx) -> "ScanAndCompose":
        d, s = ctx.deps, ctx.state
        _enter(ctx, "InventoryTarget")
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

        # Binary artifacts: record + ENQUEUE (status `queued`). Disposition is decided
        # in one place downstream — ProcessTransforms opens up the ones a provider can
        # handle (flips them `done`), and the ProcessWorkQueue loop drains the rest to
        # blocked/deferred. That single decision point is what the work queue buys us.
        has_re = d.toolchain.has_re
        binary_artifacts: list[ArtifactRef] = []
        for rel in tree.binary_paths:
            abspath = Path(s.target_path) / rel if Path(s.target_path).is_dir() else Path(s.target_path)
            kind = classify_kind(Path(rel))
            binary_artifacts.append(ArtifactRef(path=str(abspath), logical_path=rel, kind=kind))
            art_id = d.ledger.add_artifact(
                run_id=s.run_id, kind=kind if kind in BINARY_KINDS else "native-binary",
                origin="inventory", path=str(abspath), logical_path=rel,
            )
            d.ledger.enqueue(
                run_id=s.run_id, key=stable_key(rel, "scan-binary"),
                target=rel, operation="scan-binary", category="binary",
                title=f"Deep-analyse binary artifact {rel}",
                payload={"artifactId": art_id, "kind": kind},
            )

        d.ledger.enqueue(
            run_id=s.run_id, key=stable_key(str(s.target_path), "scan-source"),
            target=str(s.target_path), operation="scan-source", category="source",
            title="Native source scan", priority=20,
        )
        d.scratch["binary_artifacts"] = binary_artifacts
        _mark_op_done(ctx, "inventory")
        d.ledger.event(s.run_id, "InventoryTarget", "note",
                       {"binaryArtifacts": len(tree.binary_paths), "reInstalled": has_re})
        return ScanAndCompose()


@dataclass
class ScanAndCompose(BaseNode[MCDGraphState, MCDGraphDeps, dict]):
    async def run(self, ctx: _Ctx) -> "FetchReferences | CoverageGate":
        d, s = ctx.deps, ctx.state
        _enter(ctx, "ScanAndCompose")
        reveal_dir = str(d.paths.run_dir / "revealed")
        scanner = NativeScanner()
        try:
            observations, inv = await asyncio.to_thread(
                partial(scanner.observe, str(s.target_path), reveal_dir=reveal_dir))
            result = await asyncio.to_thread(
                partial(scanner.compose_assess_render, observations, inv, str(s.target_path)))
        except Exception as exc:  # a broken target, not a missing scanner
            _fail_op(ctx, "scan-source", repr(exc))
            d.scratch["scanner_error"] = repr(exc)
            d.ledger.event(s.run_id, "ScanAndCompose", "error", {"error": repr(exc)})
            return CoverageGate()

        _record_scan(ctx, result)
        # Raw Observation objects + inventory survive so ProcessTransforms can
        # accumulate transform-derived atoms and re-compose over the union.
        d.scratch["scan"] = result
        d.scratch["observations_raw"] = observations
        d.scratch["inv"] = inv
        _mark_op_done(ctx, "scan-source")
        d.ledger.event(s.run_id, "ScanAndCompose", "note",
                       {"observations": len(result.observations),
                        "findings": len(result.findings)})
        return FetchReferences()


@dataclass
class FetchReferences(BaseNode[MCDGraphState, MCDGraphDeps, dict]):
    """Fetch-only network: pull remote code the target *runs* (``curl … | sh``) and fold
    its bytes into the scan as recovered source — never executing it. Off unless
    ``--network fetch-only``; every URL and redirect passes the SSRF guard. Fetched code
    lands in `observations_raw`/`inv` before ProcessTransforms, so a fetched-then-
    obfuscated payload still flows through the transform fixpoint."""

    async def run(self, ctx: _Ctx) -> "ProcessTransforms":
        d, s = ctx.deps, ctx.state
        _enter(ctx, "FetchReferences")
        if d.config.network not in ("fetch-only", "dynamic"):
            return ProcessTransforms()
        observations = d.scratch.get("observations_raw")
        inv = d.scratch.get("inv")
        if observations is None or inv is None:
            return ProcessTransforms()

        from unmask.net import FetchPolicy, FetchResult, extract_fetch_targets
        from unmask.net import fetch as net_fetch
        targets = extract_fetch_targets(observations, inv)
        if not targets:
            d.ledger.event(s.run_id, "FetchReferences", "note", {"targets": 0})
            return ProcessTransforms()

        policy = FetchPolicy()
        fetchdir = d.paths.run_dir / "fetched"
        # Durable per-run fetch cache: on `unmask resume` the bytes are reused from disk
        # instead of re-hitting the (attacker-referenced) network.
        manifest_path = fetchdir / "manifest.json"
        manifest: dict = {}
        if manifest_path.exists():
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                manifest = {}

        summaries: list[dict] = []
        derived: list[DerivedSource] = []
        for i, t in enumerate(targets[: policy.max_fetches]):
            wid = d.ledger.enqueue(
                run_id=s.run_id, key=stable_key(t.url, "fetch"), target=t.url,
                operation="fetch", category="network",
                title=f"Fetch referenced URL {t.url}", payload={"sourceRel": t.source_rel})
            cached = manifest.get(t.url)
            reused = bool(cached and cached.get("path") and Path(cached["path"]).exists())
            if reused:
                res = FetchResult(url=t.url, ok=True, path=cached["path"], status=cached.get("status"),
                                  content_type=cached.get("contentType"), bytes_len=cached.get("bytes", 0),
                                  sha256=cached.get("sha256"), final_url=cached.get("finalUrl"))
            else:
                res = await asyncio.to_thread(
                    partial(net_fetch, t.url, str(fetchdir / f"t{i}"), policy))
                if res.ok and res.path:
                    manifest[t.url] = {"path": res.path, "sha256": res.sha256, "bytes": res.bytes_len,
                                       "status": res.status, "contentType": res.content_type,
                                       "finalUrl": res.final_url}
            summaries.append({
                "url": t.url, "sourceRel": t.source_rel, "ok": res.ok, "reused": reused,
                "status": res.status, "bytes": res.bytes_len, "sha256": res.sha256,
                "contentType": res.content_type, "blocked": res.blocked_reason,
                "error": res.error, "redirects": res.redirects,
            })
            if res.ok and res.path:
                origin = f"{t.source_rel}»fetch"
                derived.append(DerivedSource(root=res.path, origin=origin, method="fetch"))
                d.ledger.add_artifact(
                    run_id=s.run_id, kind="fetched-content", origin="fetch", path=res.path,
                    logical_path=f"{origin}!{os.path.basename(res.path)}",
                    metadata={"url": t.url, "sha256": res.sha256, "bytes": res.bytes_len, "reused": reused})
                d.ledger.set_work_status(wid, "done",
                    result={"sha256": res.sha256, "bytes": res.bytes_len, "reused": reused})
            else:
                d.ledger.set_work_status(wid, "blocked" if res.blocked_reason else "failed",
                    error=res.blocked_reason or res.error)

        try:
            fetchdir.mkdir(parents=True, exist_ok=True)
            manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        except OSError:
            pass

        grew = False
        if derived:
            tr = TransformResult(provider_id="net-fetch", artifact="(references)",
                                 capability="fetch", derived=derived)
            try:  # attacker-controlled fetched bytes must never crash the run
                outcome = await asyncio.to_thread(partial(
                    fold_results, [tr], sigs=None, known_families=frozenset(), workdir=str(fetchdir)))
            except Exception as exc:
                d.ledger.event(s.run_id, "FetchReferences", "error", {"error": repr(exc)})
                outcome = None
            if outcome is not None:
                observations.extend(outcome.observations)
                inv.files.extend(outcome.files)  # fold in even with 0 atoms (binary payloads)
                if outcome.dataflow:
                    inv.dataflow = {**(inv.dataflow or {}), **outcome.dataflow}
                # A fetched binary payload (packed ELF, archive, ...) is a first-class
                # artifact: enqueue it + route it to the transform fixpoint so an RE
                # provider can open it up, and so an un-analysed one is a tracked blind
                # spot rather than an invisible gap.
                bins = d.scratch.setdefault("binary_artifacts", [])
                for f in outcome.files:
                    k = classify_kind(Path(f.path))
                    if k not in BINARY_KINDS:
                        continue
                    bins.append(ArtifactRef(path=f.path, logical_path=f.rel, kind=k))
                    art_id = d.ledger.add_artifact(
                        run_id=s.run_id, kind=k, origin="fetch", path=f.path, logical_path=f.rel)
                    d.ledger.enqueue(
                        run_id=s.run_id, key=stable_key(f.rel, "scan-binary"), target=f.rel,
                        operation="scan-binary", category="binary",
                        title=f"Deep-analyse fetched binary {f.rel}",
                        payload={"artifactId": art_id, "kind": k})
                grew = bool(outcome.observations)

        d.scratch["fetch"] = {"mode": d.config.network, "fetched": summaries}
        if grew:
            d.scratch["union_grew"] = True
        d.ledger.event(s.run_id, "FetchReferences", "note", {
            "targets": len(targets), "fetched": sum(1 for x in summaries if x["ok"]),
            "reused": sum(1 for x in summaries if x.get("reused")),
            "blocked": sum(1 for x in summaries if x.get("blocked")), "grew": grew})
        return ProcessTransforms()


@dataclass
class ProcessTransforms(BaseNode[MCDGraphState, MCDGraphDeps, dict]):
    """Open up what source can't read — hand obfuscated source and binary artifacts to
    registered RE providers, rescan whatever they recover, and re-compose over the
    union. Inert without a provider: binaries stay an honest coverage blind spot.

    The loop is a fixpoint — recovered source may itself carry obfuscation or a nested
    binary, so each pass re-plans over what the last pass surfaced, bounded by
    `_MAX_TRANSFORM_PASSES`/`_MAX_TRANSFORMS`."""

    async def run(self, ctx: _Ctx) -> "ReviewFindings":
        d, s = ctx.deps, ctx.state
        _enter(ctx, "ProcessTransforms")
        scan = d.scratch.get("scan")
        observations = d.scratch.get("observations_raw")
        inv = d.scratch.get("inv")
        if scan is None or observations is None or inv is None:
            return ReviewFindings()
        # FetchReferences may already have grown the union (fetched remote code).
        fetched_grew = bool(d.scratch.pop("union_grew", False))
        providers = d.toolchain.transform_providers()

        all_obs = list(observations)
        transformed: list[str] = []
        dropped: list[dict] = []
        notes: list[dict] = []

        if providers:
            from unmask.scanner.signatures import Signatures
            sigs = Signatures.load_vendored()
            known_families = sigs.known_families()
            # Plan against the capabilities of the EXECUTION pool (providers that can
            # actually transform), not the full toolchain union — otherwise a request is
            # planned for a capability only a non-transform provider advertises, then
            # silently skipped while the artifact is already marked done in the fixpoint.
            caps = {c for p in providers for c in (getattr(p, "capabilities", []) or [])}
            workroot = d.paths.run_dir / "transform"
            pending_binaries = list(d.scratch.get("binary_artifacts") or [])
            done: set[str] = set()
            try:
                all_obs = await asyncio.to_thread(
                    partial(_run_transform_fixpoint, all_obs, inv, pending_binaries,
                            providers, caps, known_families, sigs, str(workroot),
                            done, transformed, dropped, notes))
            except Exception as exc:  # the seam must never fail the run
                d.ledger.event(s.run_id, "ProcessTransforms", "error", {"error": repr(exc)})
                all_obs = list(observations)
                transformed.clear(); dropped.clear(); notes.clear()  # roll back partial claims
            d.scratch["transforms"] = {
                "providers": [getattr(p, "id", "re-provider") for p in providers],
                "transformed": transformed, "droppedAtoms": dropped, "notes": notes,
            }

        if not (fetched_grew or transformed or dropped or notes):
            d.ledger.event(s.run_id, "ProcessTransforms", "note", {"transformed": 0})
            return ReviewFindings()

        # Re-number the union and compose ONCE over it (fetch + transform derived),
        # then re-record the ledger from the recomposed result.
        for i, o in enumerate(all_obs, start=1):
            o.id = f"obs-{i}"
        result = await asyncio.to_thread(
            partial(NativeScanner().compose_assess_render, all_obs, inv, str(s.target_path)))
        d.ledger.reset_observations(s.run_id)
        d.ledger.reset_findings(s.run_id)
        _record_scan(ctx, result)
        d.scratch["scan"] = result
        d.scratch["observations_raw"] = all_obs

        # Flip each transformed binary's scan-binary work item from blocked/deferred to
        # done — it was actually opened up this run.
        for rel in transformed:
            wid = _work_id_for(ctx, "scan-binary", rel)
            if wid:
                d.ledger.set_work_status(wid, "done",
                    result={"note": "Deep-analysed via RE provider (transform seam)."})

        d.ledger.event(s.run_id, "ProcessTransforms", "note",
                       {"transformed": len(transformed), "droppedAtoms": len(dropped),
                        "fetchedGrew": fetched_grew,
                        "observations": len(result.observations),
                        "findings": len(result.findings)})
        return ReviewFindings()


@dataclass
class ReviewFindings(BaseNode[MCDGraphState, MCDGraphDeps, dict]):
    """Optional agentic adjudication. A reviewer reads each finding's evidence and
    the overlay recomputes a *reviewed* disposition (the model judges; the rule,
    not the model, sets disposition). Off unless config.review; a missing or failed
    model is an honest coverage note, never a hard stop. Judgments persist."""

    async def run(self, ctx: _Ctx) -> "CoverageGate":
        d, s = ctx.deps, ctx.state
        _enter(ctx, "ReviewFindings")
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
        reviews, overlay = await asyncio.to_thread(partial(review_assessment, assessment, model=model))
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


@dataclass
class CoverageGate(BaseNode[MCDGraphState, MCDGraphDeps, dict]):
    """Decide the next phase from ledger state, not model output. Hands off to the
    work-queue loop, which drains whatever discovery left actionable."""

    async def run(self, ctx: _Ctx) -> "ProcessWorkQueue":
        d, s = ctx.deps, ctx.state
        _enter(ctx, "CoverageGate")
        actionable = d.ledger.actionable_count(s.run_id)
        d.ledger.event(s.run_id, "CoverageGate", "note",
                       {"actionable": actionable, "coverage": d.ledger.coverage(s.run_id)})
        return ProcessWorkQueue()


@dataclass
class ProcessWorkQueue(BaseNode[MCDGraphState, MCDGraphDeps, dict]):
    """The graph's branching loop. Lease the next actionable work item, dispatch it to a
    handler that drives it terminal (and may enqueue follow-ups), then SELF-LOOP until
    the queue is drained or the bound is hit. One item per pass, so N discovered items
    drain across N iterations — visible in the ledger's graph_events. This is where the
    pipeline stops assuming work is done inline and actually works it off; new operations
    plug in as handlers without touching the graph."""

    async def run(self, ctx: _Ctx) -> "ProcessWorkQueue | RenderReport":
        d, s = ctx.deps, ctx.state
        _enter(ctx, "ProcessWorkQueue")
        processed = d.scratch.get("wq_processed", 0)
        if processed >= _MAX_WORK_ITEMS:  # runaway backstop; surfaced, never silent
            d.ledger.event(s.run_id, "ProcessWorkQueue", "note",
                           {"stopped": "max-work-items", "processed": processed,
                            "remaining": d.ledger.actionable_count(s.run_id)})
            return RenderReport()
        item = d.ledger.lease_next_actionable(s.run_id)
        if item is None:
            d.ledger.event(s.run_id, "ProcessWorkQueue", "note",
                           {"drained": True, "processed": processed})
            return RenderReport()
        d.scratch["wq_processed"] = processed + 1
        _dispatch_work(ctx, dict(item))
        return ProcessWorkQueue()


@dataclass
class RenderReport(BaseNode[MCDGraphState, MCDGraphDeps, dict]):
    async def run(self, ctx: _Ctx) -> End[dict]:
        d, s = ctx.deps, ctx.state
        _enter(ctx, "RenderReport")
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
        transforms = d.scratch.get("transforms")
        if transforms:
            sections["transforms"] = transforms
        fetch = d.scratch.get("fetch")
        if fetch:
            sections["fetch"] = fetch

        reports_dir = d.paths.reports_dir
        reports_dir.mkdir(parents=True, exist_ok=True)
        # Only binary artifacts, not network-blocked fetch items (both use 'blocked').
        blocked_binaries = d.ledger.count_work_items(
            s.run_id, operation="scan-binary", status="blocked")

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
            await _post_report_qa(ctx, scan.assessment, d.scratch["reviews"], reports_dir)

        status = "completed" if scan is not None else "partial"
        summary = {"disposition": disposition, "findingCount": finding_count,
                   "blockedBinaries": blocked_binaries}
        d.ledger.finish_run(s.run_id, status, coverage=coverage, summary=summary)
        _write_run_json(ctx, status=status, disposition=disposition)
        d.ledger.event(s.run_id, "RenderReport", "note", summary)

        return End({
            "runId": s.run_id, "projectId": s.project_id, "runDir": str(s.run_dir),
            "status": status, "disposition": disposition, "findingCount": finding_count,
            "blockedBinaries": blocked_binaries,
            "reportPaths": {"html": str(reports_dir / "report.html"),
                            "md": str(reports_dir / "report.md"),
                            "json": str(reports_dir / "report.json")},
        })


def build_graph() -> Graph:
    """Assemble the phase graph. Rebuilt cheaply per run; nodes are stateless."""
    g = GraphBuilder(name="mcd", state_type=MCDGraphState, deps_type=MCDGraphDeps,
                     input_type=InitializeRun, output_type=dict)
    g.add(
        g.edge_from(g.start_node).to(InitializeRun),
        g.node(InitializeRun),
        g.node(InventoryTarget),
        g.node(ScanAndCompose),
        g.node(FetchReferences),
        g.node(ProcessTransforms),
        g.node(ReviewFindings),
        g.node(CoverageGate),
        g.node(ProcessWorkQueue),
        g.node(RenderReport),
    )
    return g.build()


# --- work-queue handlers ---------------------------------------------------

def _handle_scan_binary(ctx: _Ctx, item: dict) -> None:
    """A binary artifact ProcessTransforms did NOT open up (no working RE provider, or
    none with the right capability). Its disposition is an honest coverage blind spot:
    `deferred` when a provider is present but couldn't handle it, `blocked` when nothing
    is installed. Both surface in the report as 'not deeply analysed'."""
    d = ctx.deps
    # 'blocked' means no RE tooling at all; 'deferred' means an RE provider IS installed
    # but none opened THIS artifact up (wrong capability, e.g. a deobfuscate-only
    # provider, or a non-functional one). Keyed on any registered provider, not just
    # binary-capable ones, so we don't tell the user to install what they already have.
    installed = any(p.error is None for p in d.toolchain.providers)
    if installed:
        d.ledger.set_work_status(item["id"], "deferred",
            result={"note": "RE provider(s) present but none deep-analysed this artifact "
                            "(no binary-capable provider, or a non-functional one); not decompiled."})
    else:
        d.ledger.set_work_status(item["id"], "blocked",
            error="No RE provider installed (install unmask-re); binary not deeply "
                  "analysed. Reported as a coverage blind spot.")


_WORK_HANDLERS = {
    "scan-binary": _handle_scan_binary,
}


def _dispatch_work(ctx: _Ctx, item: dict) -> None:
    """Route one leased work item to its handler; an unknown operation is deferred with
    a note (never left leased — that would stall the loop)."""
    op = item.get("operation")
    handler = _WORK_HANDLERS.get(op)
    try:
        if handler is not None:
            handler(ctx, item)
        else:
            ctx.deps.ledger.set_work_status(item["id"], "deferred",
                result={"note": f"No queue handler for operation {op!r}."})
    except Exception as exc:  # a handler bug must not stall the loop
        ctx.deps.ledger.set_work_status(item["id"], "failed", error=f"{type(exc).__name__}: {exc}")
        ctx.deps.ledger.event(ctx.state.run_id, "ProcessWorkQueue", "error",
                              {"operation": op, "error": repr(exc)})


# --- helpers ---------------------------------------------------------------

def _record_scan(ctx: _Ctx, result) -> None:
    """Record a scan result's observations + findings into the ledger. Called for the
    base scan and again (after reset) over the post-transform union."""
    d, s = ctx.deps, ctx.state
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


def _run_transform_fixpoint(all_obs, inv, pending_binaries, providers, caps,
                            known_families, sigs, workroot, done, transformed,
                            dropped, notes) -> list:
    """The reveal→rescan→re-plan loop (sync; runs in a worker thread).

    Each pass is ATOMIC: its results are folded into ``all_obs``/``inv`` and its
    artifacts recorded in ``transformed`` only after the pass fully succeeds, so a
    provider (or rescan) that raises mid-pass drops that pass with a note rather than
    leaving observations, inventory, and the transformed set half-applied. Only
    artifacts that actually recovered something (``produced_anything``) are recorded as
    transformed — an error-free-but-empty result is NOT claimed as deep-analysed."""
    total = 0
    for pass_i in range(_MAX_TRANSFORM_PASSES):
        try:
            requests = plan_transforms(all_obs, inv, binary_artifacts=pending_binaries,
                                       capabilities=caps, done=done)
            requests = requests[: max(0, _MAX_TRANSFORMS - total)]
            if not requests:
                break
            for r in requests:
                done.add(r.artifact.logical_path)
            total += len(requests)
            pass_dir = os.path.join(workroot, f"pass-{pass_i}")
            os.makedirs(pass_dir, exist_ok=True)
            results = run_transform_pass(requests, providers, pass_dir)
            outcome = fold_results(results, sigs=sigs, known_families=known_families, workdir=pass_dir)
        except Exception as exc:  # a broken pass is dropped, not fatal — state stays consistent
            notes.append({"pass": pass_i, "error": f"{type(exc).__name__}: {exc}"})
            break

        # Commit — pure list/dict ops, only reached when the whole pass succeeded.
        transformed.extend(res.artifact for res in results
                           if not res.error and res.produced_anything)
        dropped.extend(outcome.dropped)
        notes.extend(outcome.notes)
        all_obs.extend(outcome.observations)
        inv.files.extend(outcome.files)
        if outcome.dataflow:
            inv.dataflow = {**(inv.dataflow or {}), **outcome.dataflow}

        # Nested binaries revealed inside recovered source drive the next pass; carry
        # forward any earlier binaries not yet requested (e.g. truncated by the budget)
        # so they aren't silently dropped.
        new_bins = [ArtifactRef(path=f.path, logical_path=f.rel, kind=classify_kind(Path(f.path)))
                    for f in outcome.files if classify_kind(Path(f.path)) in BINARY_KINDS]
        pending_binaries = [b for b in pending_binaries
                            if b.logical_path not in done] + new_bins
        if not outcome.observations and not pending_binaries:
            break

    if pending_binaries:  # never silently drop coverage — surface what wasn't reached
        notes.append({"note": "transform budget/pass limit reached; nested binaries not analysed",
                      "count": len(pending_binaries),
                      "artifacts": [b.logical_path for b in pending_binaries[:20]]})
    return all_obs


def _work_id_for(ctx: _Ctx, operation: str, target: str) -> str | None:
    row = ctx.deps.ledger.conn.execute(
        "select id from work_items where run_id=? and operation=? and target=? "
        "order by created_at limit 1", (ctx.state.run_id, operation, target)).fetchone()
    return row["id"] if row else None


def _work_id_for_op(ctx: _Ctx, operation: str) -> str | None:
    row = ctx.deps.ledger.conn.execute(
        "select id from work_items where run_id=? and operation=? order by created_at limit 1",
        (ctx.state.run_id, operation)).fetchone()
    return row["id"] if row else None


def _mark_op_done(ctx: _Ctx, operation: str) -> None:
    wid = _work_id_for_op(ctx, operation)
    if wid:
        ctx.deps.ledger.set_work_status(wid, "done")


def _fail_op(ctx: _Ctx, operation: str, error: str) -> None:
    wid = _work_id_for_op(ctx, operation)
    if wid:
        ctx.deps.ledger.set_work_status(wid, "failed", error=error)


async def _post_report_qa(ctx: _Ctx, assessment: dict, reviews, reports_dir) -> None:
    d, s = ctx.deps, ctx.state
    try:
        from unmask.qa import suggest_rule_tunings
        suggestions = await asyncio.to_thread(
            partial(suggest_rule_tunings, assessment, reviews, model=d.review_model))
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


def _write_run_json(ctx: _Ctx, *, status: str, disposition: str | None = None) -> None:
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

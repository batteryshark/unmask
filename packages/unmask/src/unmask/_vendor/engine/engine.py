"""Core scan pipeline, shared by the CLI (`scan`) and the sweep harness."""

from __future__ import annotations

from datetime import datetime, timezone

from . import inventory, rules, dataflow, callgraph, report as report_mod, source_containers
from .interpret import READINGS

# atom families whose findings dataflow can prove a path for (dropper / exfil /
# decode-exec); only files carrying one of these are worth a dataflow pass.
_DATAFLOW_FAMILIES = ("NETW", "CRED", "EXEC", "LOAD", "FSYS", "XFRM")


def observe(target: str, cppcheck: bool = False):
    """OBSERVE: inventory -> atoms -> dataflow/reachability. Returns
    (observations, inv). The shared base every v2 workload builds on; it does NO
    interpretation (no lenses, no findings). cppcheck=True adds the opt-in
    MEM.BOUNDIDX feed (no-op if cppcheck is absent)."""
    inv = inventory.build(target)
    source_containers.expand(inv)
    try:
        observations = rules.run(inv)
        if cppcheck:
            from . import cppcheck as cppcheck_mod
            extra = cppcheck_mod.analyze(inv)
            if extra:
                observations += extra
                for i, o in enumerate(observations, start=1):
                    o.id = f"obs-{i}"
        relevant = {o.path for o in observations
                    if (o.atom or "").split(".")[0] in _DATAFLOW_FAMILIES}
        inv.dataflow = dataflow.analyze_inventory(inv, only_paths=relevant)
        inv.reachability = callgraph.analyze(inv)
    finally:
        source_containers.cleanup(inv)
    return observations, inv


def observe_report(target: str, cppcheck: bool = False) -> dict:
    """A scan report of the OBSERVE layer: observations, no lens findings. The
    honest 'what the engine saw'; interpretation is each workload's own job."""
    started = datetime.now(timezone.utc).isoformat()
    observations, inv = observe(target, cppcheck)
    return report_mod.build(target, [], inv, observations, [], started, rules.ast_mode())


def run_scan(target: str, lens_ids, cppcheck: bool = False) -> dict:
    """observe -> apply the engine's named readings (from READINGS, now just the
    shared capability reading) -> report. The engine's own scan helper, used by
    the scan surface and the rule tests; products compose their own readings via
    run_readings instead. Returns a scan-report."""
    started = datetime.now(timezone.utc).isoformat()
    observations, inv = observe(target, cppcheck)
    findings = []
    for lid in lens_ids:
        fn = READINGS.get(lid)
        if fn:
            findings += fn(observations, inv)
    return report_mod.build(target, lens_ids, inv, observations, findings, started, rules.ast_mode())


def run_readings(target: str, readings, cppcheck: bool = False) -> dict:
    """observe -> apply the given reading functions -> report. The product-neutral
    way a product composes its own readings without a central registry: pass the
    reading callables directly (e.g. the mcd reading). Returns a scan-report whose
    `lenses` are the reading function names."""
    started = datetime.now(timezone.utc).isoformat()
    observations, inv = observe(target, cppcheck)
    findings = []
    for fn in readings:
        findings += fn(observations, inv)
    return report_mod.build(target, [fn.__name__ for fn in readings], inv, observations,
                            findings, started, rules.ast_mode())

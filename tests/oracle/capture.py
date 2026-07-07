#!/usr/bin/env python3
"""Freeze the OLD parallax engine's outputs as a differential oracle.

The old `engine` + `mcd_lens` are sloppy multi-iteration code that unmask is
rebuilding from scratch. But it is a *detector*, and the worst failure mode of a
rewrite is silent under-detection. So before the old engine goes away, we freeze
its observations/findings/assessment over a fixture corpus. The native rebuild is
then gated against these goldens:

    * the native scanner MUST reproduce every finding the oracle produced
      (no under-detection), and
    * every divergence is explained — where the old engine was wrong
      (false positive / mis-severity), the rebuild is intentionally better and
      the golden is updated with a recorded reason.

The oracle is a reference, not gospel. It never ships; it lives only in tests.

Usage:
    python tests/oracle/capture.py            # capture/refresh goldens
    python tests/oracle/capture.py --check    # fail if goldens are stale (CI)

The old engine is imported from a parallax-goalpacks checkout resolved via
$MCD_ORACLE_ENGINE_ROOT or a sibling search. This dependency is DEV-ONLY (oracle
capture); the shipped tool never imports it.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

# Value-based volatility normalization: keep stable ids (mcd-1, obs hashes) but
# neutralize wall-clock timestamps and per-run random ids wherever they appear
# (including when baked into a note string). Extend these if --check surfaces a
# new volatile field.
_ISO_TS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?")
_RAND_ID = re.compile(r"^(?:assess|scan)-[0-9a-f]{8,}$")

# A fixed scan timestamp so goldens are byte-stable across captures.
_FIXED_STARTED = "2026-01-01T00:00:00+00:00"

ORACLE_DIR = Path(__file__).resolve().parent
REPO_ROOT = ORACLE_DIR.parents[1]

# The corpus. Each fixture's golden is captured from a `source`:
#   "oracle" (default) — the old engine, frozen before it goes away.
#   "native"           — the native scanner, used where the old engine was WRONG
#                        (a false negative) and the rebuild is intentionally better.
#                        `reason` records why; `--check` validates against native.
CORPUS: list[dict] = [
    {"name": "evil-npm", "target": "tests/fixtures/evil-npm"},
    {"name": "benign-pkg", "target": "tests/oracle/fixtures/benign-pkg"},
    {"name": "py-curlpipe", "target": "tests/oracle/fixtures/py-curlpipe", "source": "native",
     "reason": "The old engine emits content atoms from hardcoded rules.py, not the pack, so "
               "it never saw curl/wget inside a shell string and scored setup.py's "
               "os.system('curl URL | sh') as CLEAR — a false negative on a textbook dropper. "
               "The vendored pack's remote-download-cmd rule emits NETW.HTTP for that string, "
               "so native composes BP-DROPPER (+ BP-SUPPLY on the install hook). Native is correct."},
    {"name": "obf-js", "target": "tests/oracle/fixtures/obf-js"},
]


def _resolve_engine_root() -> Path:
    candidates = []
    env = os.environ.get("MCD_ORACLE_ENGINE_ROOT")
    if env:
        candidates.append(Path(env))
    for base in [REPO_ROOT, *REPO_ROOT.parents]:
        candidates.append(base / "parallax-goalpacks")
    for c in candidates:
        if (c / "engine" / "__init__.py").is_file() and (c / "mcd_lens" / "__init__.py").is_file():
            return c.resolve()
    raise SystemExit(
        "Cannot find the old engine (parallax-goalpacks). Set $MCD_ORACLE_ENGINE_ROOT.\n"
        "This is only needed to (re)capture the oracle; the shipped tool never imports it."
    )


def _normalize_observation(o) -> dict:
    g = lambda n, d=None: getattr(o, n, d)
    return {
        "atom": g("atom"),
        "method": g("method", ""),
        "confidence": round(float(g("confidence", 0.0) or 0.0), 6),
        "path": g("path"),
        "line": g("line"),
        "rule_id": g("rule_id") or g("rule"),
        "relationships": [
            {k: r.get(k) for k in sorted(r)} for r in (g("relationships", []) or [])
        ],
    }


def _obs_sort_key(o: dict):
    return (o.get("path") or "", o.get("atom") or "", o.get("method") or "", o.get("line") or 0)


def _normalize_volatile(obj):
    """Neutralize wall-clock timestamps and per-run random ids by value, so stable
    ids (finding `mcd-1`, content-hash observation ids) are preserved."""
    if isinstance(obj, dict):
        return {k: _normalize_volatile(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_normalize_volatile(v) for v in obj]
    if isinstance(obj, str):
        if _RAND_ID.match(obj):
            return "«id»"
        return _ISO_TS.sub("«ts»", obj)
    return obj


def capture_one(name: str, target: str, eng, report_mod, rules, mcd_reading, build_assessment) -> dict:
    tpath = str((REPO_ROOT / target).resolve())
    observations, inv = eng.observe(tpath)
    findings = mcd_reading(observations, inv)
    report = report_mod.build(tpath, ["mcd"], inv, observations, findings, _FIXED_STARTED, rules.ast_mode())
    assessment = build_assessment(report)
    obs = sorted((_normalize_observation(o) for o in observations), key=_obs_sort_key)
    return {
        "observations": obs,
        "findings": _normalize_volatile(findings),
        "assessment": _normalize_volatile(assessment),
    }


def capture_one_native(name: str, target: str) -> dict:
    """Capture a golden from the NATIVE scanner — for fixtures the old engine got wrong.
    Normalized the same way as an oracle capture so the gate tests read it identically."""
    from unmask.scanner.assess import build_assessment as native_build
    from unmask.scanner.compose import compose_mcd
    from unmask.scanner.observe import observe as native_observe
    tpath = str((REPO_ROOT / target).resolve())
    observations, inv = native_observe(tpath)
    findings = compose_mcd(observations, inv)
    assessment = native_build(findings, observations, inv, tpath)
    obs = sorted((_normalize_observation(o) for o in observations), key=_obs_sort_key)
    return {
        "observations": obs,
        "findings": _normalize_volatile(findings),
        "assessment": _normalize_volatile(assessment),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="fail if goldens are stale")
    ap.add_argument("--only", nargs="*", metavar="NAME",
                    help="restrict to these fixtures (default: all)")
    args = ap.parse_args(argv)

    corpus = [f for f in CORPUS if not args.only or f["name"] in args.only]
    needs_oracle = any(f.get("source", "oracle") == "oracle" for f in corpus)

    eng = report_mod = rules = mcd_reading = build_assessment = None
    engine_version = None
    if needs_oracle:
        root = _resolve_engine_root()
        sys.path.insert(0, str(root))
        from engine import engine as eng, report as report_mod, rules  # type: ignore
        from engine import __version__ as engine_version  # type: ignore
        from mcd_lens import mcd_reading, build_assessment  # type: ignore

    golden_dir = ORACLE_DIR / "golden"
    stale: list[str] = []
    prov_fp = golden_dir / "provenance.json"
    provenance = json.loads(prov_fp.read_text()) if prov_fp.is_file() else {}
    provenance.setdefault("fixedStarted", _FIXED_STARTED)
    provenance.setdefault("fixtures", {})
    if engine_version:
        provenance["engineVersion"] = engine_version

    for f in corpus:
        name, target, source = f["name"], f["target"], f.get("source", "oracle")
        if source == "native":
            result = capture_one_native(name, target)
        else:
            result = capture_one(name, target, eng, report_mod, rules, mcd_reading, build_assessment)
        summary = {
            "source": source,
            "observations": len(result["observations"]),
            "findings": len(result["findings"]),
            "disposition": (result["assessment"].get("disposition") or {}).get("recommendation"),
            "compositions": (result["assessment"].get("summary") or {}).get("compositions"),
        }
        if f.get("reason"):
            summary["reason"] = f["reason"]
        provenance["fixtures"][name] = summary
        out = golden_dir / name
        out.mkdir(parents=True, exist_ok=True)
        for key in ("observations", "findings", "assessment"):
            text = json.dumps(result[key], indent=2, sort_keys=True) + "\n"
            fp = out / f"{key}.json"
            if args.check:
                if not fp.is_file() or fp.read_text(encoding="utf-8") != text:
                    stale.append(f"{name}/{key}.json")
            else:
                fp.write_text(text, encoding="utf-8")
        print(f"  {name:14} [{source}] obs={summary['observations']:<3} findings={summary['findings']} "
              f"disposition={summary['disposition']} {summary['compositions'] or ''}")

    prov_text = json.dumps(provenance, indent=2, sort_keys=True) + "\n"
    if args.check:
        if not prov_fp.is_file() or prov_fp.read_text(encoding="utf-8") != prov_text:
            stale.append("provenance.json")
        if stale:
            print("STALE oracle goldens:", ", ".join(stale), file=sys.stderr)
            return 1
        print("oracle goldens up to date")
    else:
        prov_fp.write_text(prov_text, encoding="utf-8")
        print(f"\nfroze oracle goldens -> {golden_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

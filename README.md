# mcd — Malicious Code Detection

> *Is this code doing something malicious — and can you prove it?*

`mcd` reads a target (source, packages, and — with the RE add-on — binaries),
composes deterministic **BP-\*** malicious-code findings over judgment-free
observations, and produces a report that keeps **severity and confidence
separate**, states a **disposition** (clear / review / quarantine), and shows its
**evidence, disproof criteria, verification steps, and coverage blind spots**. It
runs offline and executes no target code by default.

The workflow is a **phase graph**; the durable source of truth for coverage and
resumability is a **per-run SQLite ledger**. The model never decides completion —
the ledger's coverage gate does. Full rationale: [`docs/design.md`](docs/design.md).

## Two wheels, two personas

```bash
pip install unmask          # "I'm about to run this — is it suspicious?"  (static/source)
pip install unmask[review]  # + bounded, typed agentic adjudication of findings
pip install unmask-re       # "I have these binaries — rip them apart"     (decompile/triage/sandbox)
```

Core (`unmask`) stays light and offline. Reverse-engineering skills live in the
optional `unmask-re` wheel and register through the `unmask.providers` entry-point
group. **If `unmask-re` is not installed, binaries are reported as an explicit
blind spot** — never silently skipped. The command is `mcd`; the import is
`unmask`.

```bash
mcd run ./suspicious-package
mcd tree ./suspicious-package
mcd tools doctor
mcd report --run-dir .mcd/projects/<project>/runs/<run> --format html
```

## Layout

```
packages/unmask/       core: storage, ledger, graph, inventory/tree, scanner
                       adapter, report augmentation, CLI
packages/unmask-re/    heavy: RE provider registration (capability stub today)
docs/design.md         the graph + ledger design of record
```

## Status (first build cut)

Runnable end to end: `run` walks the target, generates a bounded tree, runs the
deterministic scanner (parallax `engine` + `mcd_lens`) behind a `Scanner` adapter,
persists observations/findings to the ledger, routes binaries through the RE
plugin boundary, and renders `report.{html,md,json}` from the run directory.

The scanner (parallax `engine` + `mcd_lens`, both pure stdlib) and the taxonomy
signature data are **vendored into the `unmask` wheel** (`_vendor/` and
`taxonomy/vendored/`), so core is self-contained — no sibling
`parallax-goalpacks` / `parallax-taxonomy` checkout is needed at runtime.
`--scanner-root` / `$UNMASK_SCANNER_ROOT` remain only as a dev override for
hacking against a live checkout. Re-vendor with
`python packages/unmask/scripts/vendor.py` (CI staleness check: `--check`).
The phases run on a small internal
runner shaped for a drop-in swap to Pydantic Graph. See `docs/design.md` for the
full milestone plan (container expansion, decompilers, agentic review, network
fetch, MCP surface, post-report QA).

Apache-2.0

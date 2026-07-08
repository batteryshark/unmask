<p align="center">
  <img src="docs/assets/unmask-logo.png" alt="unmask" width="240">
</p>

# unmask

*Malicious Code Detection: is this code doing something malicious, and can you prove it?*

`unmask` reads a target (source, packages, and, with the RE add-on, binaries), composes
deterministic **BP-\*** malicious-code findings over judgment-free observations, and
produces a report that keeps **severity and confidence separate**, states a **disposition**
(clear / review / quarantine), and shows its **evidence, disproof criteria, verification
steps, and coverage blind spots**. It runs offline and executes no target code by default.

The workflow is a **phase graph**; the durable source of truth for coverage and
resumability is a **per-run SQLite ledger**. The model never decides completion; the
ledger's coverage gate does. Full rationale: [`docs/design.md`](docs/design.md).

## Two wheels, two personas

```bash
pip install unmask          # "I'm about to run this, is it suspicious?"  (static/source)
pip install unmask[review]  # + bounded, typed agentic adjudication of findings
pip install unmask-re       # "I have these binaries, rip them apart"     (decompile/triage/sandbox)
```

Core (`unmask`) stays light and offline. Reverse-engineering skills live in the optional
`unmask-re` wheel and register through the `unmask.providers` entry-point group. **If
`unmask-re` is not installed, binaries are reported as an explicit blind spot**, never
silently skipped.

```bash
unmask run ./suspicious-package
unmask tree ./suspicious-package
unmask tools doctor
unmask report --run-dir .mcd/projects/<project>/runs/<run> --format html
```

## Layout

```
packages/unmask/       core: storage, ledger, graph, inventory/tree, scanner,
                       contextual attenuators, report augmentation, CLI
packages/unmask-re/    RE skills: unpack, js-deobfuscate, jvm/dotnet/pyc-decompile,
                       bin-triage, covert-scans, secrets-scan
docs/design.md         the graph + ledger design of record
```

## Status (v0.1)

Runnable end to end: `run` walks the target, generates a bounded tree, runs the
deterministic scanner, persists observations and findings to the per-run SQLite ledger,
routes binaries and obfuscated source through the **RE transform seam** (deobfuscate /
decompile / unpack via the vendored RE skills in `unmask-re`), optionally fetches
referenced remote code as evidence (`--network fetch-only`), runs an **agentic
adjudication** overlay (`--review`), and renders `report.{html,md,json}` with
syntax-highlighted evidence, a table of contents, and severity filter chips.

**Deterministic false-positive control.** Contextual attenuators keep benign repos out of
auto-quarantine: documented installer idioms (`curl … astral.sh/uv/install.sh | sh`),
CI/Dockerfile/install-script contexts, documentation files, and download-page UI routes
attenuate confidence without removing findings, so a normal codebase scans to
`review`/`clear` while a genuine dropper still quarantines. The attenuators are a
post-compose interpretation layer; the compose oracle stays judgment-free.

**Batched agentic review.** Findings drain through a pydantic-ai record tool in bounded
chunks, so a 50+ finding run can't hit an output-size limit; any finding the model skips
falls through to `needs_human`, never a silent drop.

See `docs/design.md` for the full design and the deferred milestones (sandbox providers
beyond local, dynamic execution, tool-install CLI, registry metadata; documented blind
spots in v0.1).

### What's a blind spot in v0.1

- **Dynamic execution / sandboxing.** No VM/container/network-capture; static and transform
  only (decompilers extract source, never run it).
- **Tool-install CLI.** jadx/ilspycmd/ghidra are BYO (prereq-gated: missing means an honest
  blind spot, not a crash). `unmask tools doctor` reports what resolved.
- **Registry metadata.** npm/PyPI enrichment is offline; confidence reflects static evidence
  without external corroboration.

Apache-2.0

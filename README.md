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

## Install

Not on PyPI yet — run it from source with [uv](https://docs.astral.sh/uv/):

```bash
git clone https://github.com/batteryshark/unmask
cd unmask
./setup.sh          # installs everything, optionally configures a review model, checks RE tools
```

`setup.sh` is interactive and safe to re-run. To do it by hand instead:

```bash
uv sync                            # core + RE add-on + review + MCP, in one .venv
cp .env.example .env               # then edit, only if you want --review (model endpoint + key)
uv run unmask tools doctor         # what's installed, what's missing, and how to fix it
uv run unmask run ./suspicious-package
```

(From a source checkout, commands run as `uv run unmask …`, or activate `.venv` and drop the prefix.)

## Two wheels, two personas

`uv sync` brings up both wheels this repo ships:

- **`unmask`** — the light, offline core: static/source analysis, graph + ledger, report.
- **`unmask-re`** — the reverse-engineering add-on: binary triage, decompilers, deobfuscation.
  It registers through the `unmask.providers` entry-point group. **Without it, binaries are
  reported as an explicit blind spot, never silently skipped.** A few decompilers also need an
  external tool (jadx, ilspycmd); `unmask tools doctor` shows which resolved and how to get the
  rest — each is optional and gates only its own binary type.

Once published, the two wheels install independently from PyPI: `pip install unmask` (core),
`pip install unmask[all]` (everything), `pip install unmask-re` (the RE add-on on its own).

### Configuring review

The deterministic scan needs no model and runs offline. The `--review` overlay (bounded, typed
agentic adjudication of findings) needs one: set it in `.env` — see [`.env.example`](.env.example).
Pick a provider preset (`openai`, `anthropic`, `lmstudio`, `minimax`, `zai`, or `custom` for any
OpenAI/Anthropic-compatible endpoint), give it a model id and a key, and `unmask tools doctor`
will confirm it's wired up. `setup.sh` writes this for you.

```bash
uv run unmask run ./suspicious-package
uv run unmask tree ./suspicious-package
uv run unmask tools doctor
uv run unmask report --run-dir .mcd/projects/<project>/runs/<run> --format html
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

See [`docs/design.md`](docs/design.md) for the full design and the deferred milestones
(sandbox providers beyond local, dynamic execution, tool-install CLI, registry metadata;
documented blind spots in v0.1).

### What's a blind spot in v0.1

- **Dynamic execution / sandboxing.** No VM/container/network-capture; static and transform
  only (decompilers extract source, never run it).
- **Tool-install CLI.** jadx/ilspycmd/ghidra are BYO (prereq-gated: missing means an honest
  blind spot, not a crash). `unmask tools doctor` reports what resolved.
- **Registry metadata.** npm/PyPI enrichment is offline; confidence reflects static evidence
  without external corroboration.

## License

Apache-2.0 — see [LICENSE](LICENSE).

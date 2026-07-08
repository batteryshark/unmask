# muster

*A ledgered investigation runtime.*

A durable, coverage-gated, resumable work-graph runtime with bounded adaptive model
steps — the provable-workload core extracted from **unmask** (malicious-code detection)
and intended to be shared by **lucent** (code understanding) and **rekit-factory** (RE /
debugger / compat-patching).

muster owns the **spine**:

- **run identity + on-disk layout** — content-addressed project/run ids, one SQLite
  ledger per run (`muster.paths`)
- **the ledger** — coverage-gated work queue, exactly-once durability, audit, resume
- **the graph runner** — the work-queue drain loop + handler registry
- **the patterns** — durable questions (`needs_input`), model-proposed leads, adversarial
  verification, per-role model routing

A consumer registers its **domain** — its tables, nodes, work handlers, and coverage
predicate — by composition; muster never knows about the domain. See the extraction seam
in `docs/investigation-engine-seam.md` (in the unmask repo during extraction).

> Extraction in progress. Slice 1 (run identity + paths) has landed; the ledger core and
> graph scaffolding follow.

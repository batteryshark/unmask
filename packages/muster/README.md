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
  (`muster.Ledger`; a consumer layers its domain tables via `extra_schema`/`reset_tables`)
- **the graph scaffolding** — base `GraphState`/`GraphDeps`, `atomic_write`, phase-entry
  `enter`, and the `WorkDispatcher` (work-queue drain: an `operation → handler` registry +
  lease/dispatch), in `muster.graph`
- **the patterns** — durable questions (`ask` → `needs_input`); model-proposed leads,
  adversarial verification, and per-role model routing (still consumer-side, generalising
  next)

A consumer registers its **domain** — its tables, nodes, work handlers, and coverage
predicate — by composition; muster never knows about the domain. muster owns the
*mechanism* the nodes run on, not the pydantic-graph nodes themselves (those are
concrete-typed and edge-inferred, so they stay with the consumer). See the extraction
seam in `docs/investigation-engine-seam.md` (in the unmask repo during extraction).

> Extraction in progress. Landed: slice 1 (run identity + paths), slice 2 (the ledger
> core / spine vs domain), slice 3 (graph scaffolding + durable questions + the work
> dispatcher). Next: generalise the lead / adversarial-verify / model-routing patterns,
> then validate against a second consumer.

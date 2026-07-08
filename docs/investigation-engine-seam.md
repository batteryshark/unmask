# The investigation engine seam

*A durable, coverage-gated, resumable work-graph runtime with bounded adaptive model
steps.* Today it lives inside unmask; it is written to be extracted into a shared engine
that unmask, **lucent** (code understanding), and **rekit-factory** (RE / debugger /
compat-patching) all depend on. This note fixes the boundary **before** we build leads,
so the primitives are engine-shaped from the start and extraction is a *move*, not a
rewrite.

The one-line shape all three share: **a guaranteed-coverage investigation with adaptive
leads** — enumerate a surface, drain it to N/N, accumulate durable findings, follow
lateral leads the fixed enumeration missed, survive crashes, and keep a queryable audit
of what was done and why.

## Non-negotiable guarantees (the engine enforces these; consumers can't opt out)

- **Coverage** — enumerate → drain → prove N/N covered. A `done` unit means "worked
  off," not "asked." Nothing off-surface is silently dropped; residue is surfaced.
- **Durability / exactly-once** — SQLite ledger + content-addressed IDs; a crash resumes
  from the ledger, re-recording without duplication.
- **Auditability** — every step is a queryable ledger row (work item, event, artifact),
  not an opaque transcript.
- **Bounded, attributed cost** — fan-out caps, loop-until-dry with a ceiling, budget.
- **Invariant: the model steers *where*; the deterministic layer judges *what*.** Model
  work proposes investigations and verifies borderline calls; it never authors a verdict
  or a coverage claim. Leads are **additive** to guaranteed coverage, never a substitute.

## Engine core (generic — owns the spine, no domain knowledge)

- **Ledger**: `runs`, `work_items`, `graph_events`, `artifacts` + coverage; API
  `enqueue` / `lease_next_actionable` / `set_work_status` / `count_work_items` /
  `reset_run_derived` / `finish_run`. (Domain tables like `observations`/`findings` are
  *not* here — see hooks.)
- **Graph scaffolding**: the `BaseNode` phase pattern, `_enter`/event recording, the
  `ProcessWorkQueue` drain loop + the `_WORK_HANDLERS` registry, `_atomic_write`.
- **Storage/paths**: run/project identity, content-addressed IDs, the run-dir layout,
  the resume driver (`reset_run_derived` + re-drive).
- **Patterns**: the *lead* work-item lifecycle (propose → enqueue → drain → fold) and the
  *adversarial-verify* pass (N perspective-diverse skeptics vote on a borderline call).

## The four extension hooks (a consumer registers these; nothing else)

| Hook | What the consumer supplies |
|------|----------------------------|
| **1. Observation/finding record** | the domain tables + record shape (what a "fact"/"finding" is) |
| **2. Work operations + handlers** | `operation -> handler(ctx, item)`; each drives its item terminal and may enqueue follow-ups |
| **3. Coverage predicate** | what enumerates "the surface" and what counts as "covered" |
| **4. Lead types + producer + handlers** | residue → proposed investigations (bounded model), and how each lead kind executes deterministically |

### How the three consumers instantiate the hooks

| Hook | unmask (detection) | lucent (code understanding) | rekit-factory (RE / compat) |
|------|--------------------|-----------------------------|-----------------------------|
| **1. record** | atoms → `BP-*` findings | code facts (symbols, types, effects) | issues / repros / patches |
| **2. ops + handlers** | scan-binary, deobfuscate, fetch, transform | read-symbol, trace-callgraph, resolve-import | run-debugger, apply-patch, test-compat, bisect |
| **3. coverage** | taxonomy rules × artifacts | symbols / call-paths understood | compat issues enumerated × addressed |
| **4. leads** | "novel packer here" / "cross-file loader pair" | "unexplained symbol" / "dynamic dispatch to trace" | "untested compat hypothesis" / "candidate patch to try" |

The engine's `work_items`/`events`/`artifacts` are already domain-neutral; only the
observation/finding tables and the four hooks vary. That is the whole seam.

## Extraction sequencing (why we're not making a new repo yet)

1. Build `ProposeLeads` + `lead` work-item + adversarial-verify **in unmask, behind this
   boundary** (generic lead/coverage/handler types; no atom/finding coupling in the
   primitive).
2. **Extract in place** to a workspace package (`packages/<engine>`); unmask depends on
   it. This forces the seam to be explicit and tested with zero new-repo overhead.
3. **Second consumer validates it** — point lucent or rekit-factory at the package and
   fix what the contract got wrong across domains.
4. **Graduate** to its own private repo, consumed as a versioned dependency (each project
   is already a separate repo). Vendor as a *dependency*, not as data — it's code.

*Naming is deferred; the common noun is "a ledgered investigation runtime."*

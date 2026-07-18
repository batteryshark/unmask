# unmask — architecture

unmask answers one question: **is this code doing something malicious, and can you
prove it?** It reads a target (source, packages, and — with the RE add-on — binaries),
records judgment-free observations, composes them into deterministic `BP-*`
malicious-code shapes, and produces a report that keeps **severity and confidence
separate**, states a **disposition** (clear / review / quarantine), and shows its
evidence, disproof criteria, verification steps, and coverage blind spots. It runs
offline and executes no target code by default.

The design principle everything else follows from: **the deterministic scanner and its
report are the quality bar.** Bounded model steps assist — reviewing cited evidence,
proposing follow-ups — but never author a verdict or a coverage claim. "Ask an agent if
the code is malicious" is explicitly not the product.

## The layers

- **Detection** (unmask core): observations → `BP-*` compositions → disposition → report.
- **Meaning** (a vendored taxonomy): the atom ontology, malicious-code indicators,
  `BP-*` composition rules, verification guidance, and response tiers — shipped as
  *data*, not engine logic.
- **RE transform seam** (`unmask-re`): unpack / deobfuscate / decompile untrusted input
  under a sandbox policy, then rescan what it recovers.
- **Runtime** (muster): the phase graph, the SQLite coverage/resume ledger, the
  work-queue drain. **The ledger's coverage gate — not the model — decides when a run is
  done.**

## The pipeline

```
observe(target)              -> observations + a bounded inventory tree
compose(observations)        -> BP-* findings (severity, confidence, cited evidence,
                                 disproof criteria, verification steps, response tier)
attenuate(findings, context) -> confidence adjusted for benign context (not removed)
dispose(findings)            -> clear | review | quarantine  (deterministic)
render(assessment)           -> self-contained report.{html,md,json}
```

An optional `--joern` deep-static step sits after broad observation and transform
rescanning, once the deterministic composition layer has identified an unresolved flow
question. It invokes Rekit's declarative `joern-slice` profile once per selected source
frontend and feeds structural evidence back through the existing provenance and
confidence policy. It does not add findings, replace Tree-sitter coverage, execute target
code, or claim cross-language flow. Missing runtime coverage and implicit sink selections
remain explicit report limitations.

**Severity ≠ confidence.** Severity is *how bad this is if real* (fixed by the shape).
Confidence is *how sure we are* (moved only by policy-derived, auditable rules). A
critical-severity finding at low confidence is a `review`, not a `quarantine`.

**Disposition is deterministic.** It is a function of the surviving findings' severity
and confidence, not a model's opinion. The model can move confidence within policy
bounds through a validated record tool; it cannot set the disposition.

## Observations and the taxonomy

**Observations are judgment-free atoms.** Each records a path, an evidence snippet, a
`method` (how it was found — `content-regex`, callee match, `covert-scan`), and a
confidence. An atom names *what was seen* (`NETW.HTTP`, `EXEC.SHELL`, `XFRM.ENCODE`,
`XFRM.BITWISE`, `ENVI.ENVCHECK`, `LOAD.EVAL`, …), never *whether it is malicious*.

Two precision tiers matter downstream:
- **Recovered payloads** — a decoder actually ran and produced a concrete plaintext
  (e.g. an XOR-decoded domain). These are *facts*.
- **Pattern matches** — a heuristic fired on source (a callee name, a regex). These are
  *supporting signals*, frequently benign in isolation.

**`BP-*` findings compose observations into malicious-code shapes** — `BP-DROPPER`
(fetch → write → execute), `BP-OBFEXEC` (decode → execute), `BP-OBFUSCATION`,
`BP-BACKDOOR`, `BP-EXFIL`, `BP-TIMEBOMB`, `BP-EVASION`. Compositions require
co-occurrence, and several require a proven dataflow link, not just two atoms in the
same file.

**Attenuators** are a post-compose interpretation layer: documented installer idioms
(`curl … | sh` in a README), CI/Dockerfile contexts, and documentation files reduce a
finding's *confidence* without deleting it — so a normal repo scans to `review`/`clear`
while a genuine dropper still quarantines. The compose step itself stays judgment-free;
attenuation is separate and auditable.

## The runtime: phase graph + ledger

The workflow is a **phase graph** (discover → observe → transform → compose → review →
report). The durable source of truth is a **per-run SQLite ledger**, not the graph.
Discovery can add work while a run is in progress (a carved archive member, a decompiled
class), and the ledger tracks coverage across it.

**The model never decides completion.** A run is done when the ledger's coverage gate is
satisfied — every discovered work item scanned or explicitly recorded as a blind spot.
Because state is durable, a crashed or interrupted run **resumes** from the ledger and
reuses already-fetched content.

## The RE transform seam

Binaries and obfuscated source route through `unmask-re`, an optional wheel that
registers reverse-engineering skills via the `unmask.providers` entry point (unpack,
deobfuscate, decompile, triage). Each transform runs under the sandbox policy below,
writes recovered source to the run directory, and **feeds it back as new work to
rescan.** If `unmask-re` is not installed, binaries are reported as an explicit blind
spot — never silently skipped.

## Bounded model review (optional)

With `--review`, an agentic layer adjudicates findings *after* the deterministic scan. It
is deliberately narrow:

- It reviews **one finding and its cited evidence at a time**, from the evidence alone —
  it does not read the whole repository or invent evidence.
- Its output is a typed `FindingReview` (verdict + a policy-bounded confidence),
  recorded through a validated tool. It **cannot** author report prose, change severity,
  or decide completion.
- Cited evidence is presented in **precision tiers**: recovered payloads are surfaced
  un-clipped and marked dispositive; supporting pattern-matches are clipped. A recovered
  suspicious indicator (a concealed domain, command, or credential) is not diluted or
  averaged away by benign boilerplate around it.
- Anything the model skips or cannot judge falls to `needs_human` — never a silent drop.

A separate `--verify` pass can adversarially re-check downgrades before they stand, and a
post-report QA step may propose rule-tuning candidates for suppressed findings. QA
suggestions are advisory: they never mutate findings, rules, or taxonomy automatically.

## Sandboxing tiers

MCD handles hostile input, so anything running a tool over untrusted bytes runs under an
explicit tier.

**Tier 0 — static read-only (default).** Read files, parse source, extract strings and
metadata. No target execution; no network beyond the model provider if review is enabled.

**Tier 1 — trusted tools over untrusted input** (archive extraction, decompilers,
strings/import extraction, tree-sitter). Target mounted read-only; writable output only
in the run directory; no network; CPU/memory/output/file-count/time limits; tool
stdout/stderr and version recorded.

**Tier 2 — limited network evidence retrieval** (a `curl … | sh` remote script, a
second-stage download, registry metadata). HTTP(S) GET/HEAD only; no execution of fetched
content; no credentials; private/link-local/localhost/metadata endpoints blocked; redirect
and size limits; content saved as an artifact and enqueued as new work; the fetch recorded.

**Tier 3 — dynamic execution** (run a branch in a VM/container, capture network against a
sinkhole, emulate a fragment). Explicit user approval; isolated environment; no real
credentials; no host-target write access; network sinkholed or allowlisted; full audit
log. Never required for the default disposition.

## Network policy

The default is offline. When retrieval is enabled it is read-only and SSRF-guarded:
GET/HEAD only, no credentials, redirects bounded, and every resolved address checked to be
public (private ranges, link-local, localhost, and cloud metadata endpoints are refused,
including after DNS rebinding). Fetched content is never executed — it becomes an
artifact and new work to scan.

## Security invariants

1. Target code is never executed in the default path.
2. Fetched remote content is never executed by the fetch node.
3. Model output never directly selects run completion.
4. Model output never mutates the ledger except through validated record tools.
5. Every external command, network fetch, and approval is recorded in the ledger.
6. Missing coverage is visible in the report.
7. Severity is not changed by reviewer whim; confidence changes are policy-derived and
   auditable.
8. Post-report QA never mutates findings, rules, or taxonomy automatically, and any
   noise-reduction suggestion must state its false-negative risk.

## Vendoring

Two inputs are vendored into the wheels as data so a scan is self-contained:

- The **taxonomy** (signature packs, compiled to JSON) → `src/unmask/taxonomy/vendored/`,
  refreshed by `packages/unmask/scripts/vendor.py`.
- The **RE skills** → `unmask-re`, refreshed by `packages/unmask-re/scripts/sync_skills.py`.

Both carry a manifest recording the source commit and per-file hashes so drift is
detectable in CI.

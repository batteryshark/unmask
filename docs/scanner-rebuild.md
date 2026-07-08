# Scanner rebuild plan

Status: in progress. The scanner is being rebuilt from scratch as clean, native
`unmask.scanner` code. The old parallax `engine` + `mcd_lens` are sloppy
multi-iteration code and are **not** the target — nothing in them is sacred. The
durable asset is the **detection knowledge** (the rules-as-data packs in
`parallax-taxonomy`), which we vendor, not the engine mechanics.

## The one rule: no under-detection

This is a *detector*. The worst failure of a rewrite is silently ceasing to catch
something the old engine caught. So the old engine is frozen as a throwaway
**differential oracle** before it disappears, and the rebuild is gated against it:

- `tests/oracle/capture.py` runs the old engine (dev-only, imported from a
  `parallax-goalpacks` checkout via `$MCD_ORACLE_ENGINE_ROOT`) over a fixture
  corpus and freezes normalized observations / findings / assessment into
  `tests/oracle/golden/`. Volatile ids/timestamps are normalized so goldens are
  byte-stable; `capture.py --check` fails CI when stale.
- `tests/oracle/test_oracle.py` asserts the **active** scanner never drops an atom,
  a BP-\* composition, or weakens a disposition vs the goldens.

The oracle is a **reference, not gospel**. Where the old engine is wrong, the
rebuild is intentionally better: update the golden with a recorded reason, never
weaken the assertion. Known divergence candidates already visible:

- `py-curlpipe` (setup.py `curl|sh` + `exec(fetch())`) → old engine reports
  **clear/0 findings**: bare install-time exec is routed to the capability lens,
  not claimed as malice. Revisit whether MCD should flag this.

## Taxonomy completeness — the real gap

Slice 2 surfaced the pivotal finding: the vendored packs are an **incomplete
migration** of what the reference engines detect. The engines (both goalpacks and
`parallax/prlx`) still emit atoms from hardcoded `rules.py` regexes, legacy callee
tables, and manifest/supply algorithms that never made it into pack data. So a
purely pack-driven scanner under-detects until the gap is closed. The gap splits
in two:

* **Data-shaped → belongs in the packs.** Callee/content classifications that are
  just data. Fix by adding to `parallax-taxonomy` (authorized). First contribution:
  `sig.load.eval.python.dynamic-exec` — python `exec`/`compile` now classify as
  `LOAD.EVAL` (code execution) instead of the universal `EXEC.PROC` (posix process
  exec), exact-match to avoid `re.compile` false positives. Closed py-curlpipe's
  callee gap. Edit the `.yaml` source + regenerate the `.json` (Ruby
  `scripts/build-signature-json`; note: system Ruby 2.6's strict Psych rejects the
  pack — needs a newer Ruby, or hand-sync the json as done here) + re-vendor.
* **Algorithm-shaped → must be native code.** Not signatures: `manifest.npm.lifecycle`
  / `manifest.pypi.setup` (PKGM.INSTALL), `supply.undeclared` (PKGM.UNDECLARED),
  and arg-inspecting detections like `Buffer.from(x,'base64')` → XFRM.ENCODE.
  Reimplement cleanly in `unmask/scanner/observe/` (manifest + supply passes).

**Oracle coupling:** goalpacks reads the *live* sibling `parallax-taxonomy`, so a
pack edit shifts the reference too. After any authorized pack change, re-run
`tests/oracle/capture.py` and confirm atoms/counts are unchanged (improvement) or
explained. The exec fix left all corpus atom-sets and counts identical.

## Target architecture

```
unmask/scanner/                native, clean, consumes vendored packs
  taxonomy/vendored/           allowlisted parallax-taxonomy + content-hash manifest
                               (signatures/ = runtime packs; ontology, lenses/mcd,
                                reference, enrichment, investigation = meaning)
  signatures/   pack reader + matcher   (proven design: TS scan-core hit 291/291)
  observe/      walk -> inventory -> extract (callees, content, imports) -> atoms
  compose/      atoms -> BP-* malicious-code findings   (the MCD lens)
  assess/       disposition, severity ⊥ confidence, correlation, coverage
  report/       html / md / json
```

Design principles carried over from the taxonomy/engine split:

- The scanner owns **mechanics** (parsing, matching, evidence extraction, proof
  accounting, rendering). The taxonomy owns **vocabulary and meaning** (surface→atom
  mappings, BP-\* definitions, verification/response prose). Scanner code hardcodes
  detector mechanics and stable rule ids, never BP-\* prose.
- Judgment-free **atoms** first (what code *can do*), then **BP-\*** compositions
  over atoms, then a deterministic **disposition** (a next-action, not a verdict).
- Severity (how bad if real) is reported separately from confidence (how sure);
  every finding states what would disprove it.

## Slice order (each gated against the oracle)

1. **Packs + matcher substrate** — ✅ DONE. Native `unmask.scanner.signatures`
   reader/matcher (callee / content / import surfaces) consuming the vendored
   packs. Callee classification is **parity-locked** to the reference matcher:
   5644/5644 candidate `(callee, lang)` pairs agree (`tests/test_signatures.py`).
2. **Source observe** — ✅ DONE. `observe(target)` assembles four passes and reaches
   **no under-detection across the whole corpus** (`tests/test_observe.py` gates it):
   - `observe/inventory.py` — data-driven walk + classify (from
     `reference/file-classification.json`; no hardcoded tables).
   - `observe/content.py` — content-atom extraction via the slice-1 matcher.
   - `observe/callee.py` — **AST** call extraction (tree-sitter, core dep) with a
     regex fallback, behind one `extract_calls` interface → `classify_callee`.
   - `observe/manifest.py` — `package.json` lifecycle + `setup.py` → PKGM.INSTALL
     with the `manifest-entrypoint` relationship BP-SUPPLY needs.
   - `observe/supply.py` — phantom/undeclared imports → PKGM.UNDECLARED
     (ecosystem-scoped stdlib check, from `reference/standard-libraries`).
   - Two pack contributions closed the data-shaped gaps: `sig.load.eval.python`
     (exec/compile→LOAD.EVAL) and `sig.xfrm.encode.base64` (base64/buffer→XFRM.ENCODE).
     PKGM.* remained algorithm-shaped → native manifest/supply passes.
   - Not yet wired into `unmask run` (the transitional `_vendor` backend still serves the
     graph); cut over happens after the compose slice reproduces the BP-* readings.
3. **Compose** — ✅ DONE. `unmask/scanner/compose/` (all 16 BP-* compositions, clean;
   `inventory.purpose` for BP-TROJAN). `tests/test_compose.py` confirms native compose
   over native observe reproduces the oracle findings' composition/severity/confidence
   exactly (evil-npm → BP-SUPPLY/OBFEXEC/BACKDOOR/TROJAN; obf-js → BP-OBFEXEC; else none).
4. **Assess + report** — ✅ DONE. `unmask/scanner/assess/` — deterministic disposition
   (clear/review/quarantine, severity⊥confidence), correlations, coverage, executive
   summary (`tests/test_assess.py` gates disposition + summary vs oracle), plus a clean
   native renderer (json/md/self-contained html — a rebuild, not the 920-line port).
   `NativeScanner` (`scanner/native.py`) wires observe→compose→assess→render behind the
   `Scanner` protocol, and `unmask run` is cut over to it.
5. **`_vendor` deleted.** The transitional engine+mcd_lens copy and the ParallaxScanner
   adapter are gone; the scanner is 100% native `unmask.scanner`. The slice-1 parity is
   frozen to `tests/fixtures/callee_parity_map.json` (5756 entries) and the oracle gate
   now measures the native scanner. `taxonomy/vendored/` (packs + reference data) stays —
   that is the detection knowledge, not engine code.
3. **Compose** — atoms → BP-\* findings (BP-SUPPLY / BP-OBFEXEC / BP-DROPPER /
   BP-BACKDOOR / BP-TROJAN / …). This is `mcd_lens.readings` rebuilt clean.
4. **Assess + report** — disposition, correlation, coverage, and html/md/json
   render. Then cut `unmask run` over to native and **delete `_vendor/`**.
5. **Binary / dataflow / supply / enrichment** — later, and binary work belongs to
   `unmask-re` (persona 2), not core.

## Runtime state (native)

- `_vendor/{engine,mcd_lens}` — **deleted.** The scanner is fully native
  `unmask.scanner` (`NativeScanner`); there is no old-engine code left in the wheel.
- `taxonomy/vendored/` — allowlisted parallax-taxonomy (packs + reference) +
  `taxonomy-manifest.json` (source commit pinned). This is the detection *data* the
  native scanner reads; it stays.
- Re-vendor via `packages/unmask/scripts/vendor.py` (`--check` fails CI when the
  vendored copy is stale). The code copy is a one-time bootstrap; the taxonomy
  copy is refreshed from the `parallax` repo.

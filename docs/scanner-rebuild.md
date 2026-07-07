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
2. **Source observe** — walk + inventory + extract source callees and content
   matches → atoms with confidence/method/location/evidence. The callee extraction
   (tree-sitter or a disciplined fallback) is the big piece.
3. **Compose** — atoms → BP-\* findings (BP-SUPPLY / BP-OBFEXEC / BP-DROPPER /
   BP-BACKDOOR / BP-TROJAN / …). This is `mcd_lens.readings` rebuilt clean.
4. **Assess + report** — disposition, correlation, coverage, and html/md/json
   render. Then cut `mcd run` over to native and **delete `_vendor/`**.
5. **Binary / dataflow / supply / enrichment** — later, and binary work belongs to
   `unmask-re` (persona 2), not core.

## Transitional state (today)

- `_vendor/{engine,mcd_lens}` — the old engine, **vendored into the wheel** so the
  tool is self-contained (no external ROOT). This is the temporary backend behind
  `unmask.scanner.ParallaxScanner`; it is deleted at the end of slice 4.
- `taxonomy/vendored/` — allowlisted parallax-taxonomy + `taxonomy-manifest.json`
  (source commit pinned). Consumed by the transitional engine now (via
  `PRLX_TAXONOMY_ROOT` set to the bundled copy) and by native slices next.
- Re-vendor via `packages/unmask/scripts/vendor.py` (`--check` fails CI when the
  vendored copy is stale). The code copy is a one-time bootstrap; the taxonomy
  copy is refreshed from the `parallax` repo.

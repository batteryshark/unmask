# engine — vendored parallax deterministic engine

Shared, repo-root component of `parallax-goalpacks`. This is a verbatim vendor of
the package-neutral Parallax detection engine (upstream `parallax/prlx/prlx/`,
formerly published as `prlx-engine`), importable as `engine`. Goalpacks and skills
that want **deterministic** code understanding (tree-sitter extraction → parallax
taxonomy atoms) depend on this instead of pure-LLM reading.

> A future cleanup epic will modularize this. For now it is a flat vendored copy so
> the source→atoms path works unchanged.

## The path we vendored for

```
engine.observe_report(target)
  -> inventory.build + source_containers.expand
  -> rules.run          (tree-sitter extraction; degrades to regex without tree-sitter)
  -> model.Observation atoms
  -> dataflow / callgraph
  -> report.build        (scan-report dict; observations carry the atoms)
```

## What was kept vs trimmed

Kept (the hard import closure of `observe_report`): `engine, inventory,
source_containers, binary, bincaps, rules, dataflow, callgraph, report, model,
signatures, paths, runtime, claims, supply, enrichment, interpret/`.

`binary.py`/`bincaps.py` are kept because `source_containers.py` imports `binary`
at module top level (and `binary` re-imports `rules.scan_strings`); they are pure
stdlib (struct/zipfile/hashlib), no external binary tooling, so they are part of
the import closure, not an optional add-on.

Trimmed (not on the `observe_report` path — surfaces, storage, opt-in tooling):
`cli.py, runner.py, store.py, ledger.py, qa.py, dashboard.py, product_quality.py,
cppcheck.py, coverage.py, validate.py, core/, workloads/`. The only reference to a
trimmed module is a `cppcheck` import inside `observe()` guarded by `cppcheck=True`
(default `False`, never taken by the observe path).

Third-party deps: `jsonschema>=4.18` (signature-pack validation) and, for AST mode,
`tree-sitter==0.25.2` + `tree-sitter-language-pack==1.12.0`. Without tree-sitter the
engine degrades to regex fallback (`rules.ast_mode()` reports which).

## Taxonomy resolution

The engine reads the callee→atom signature pack from a parallax-taxonomy layout.
Resolution order (`engine/paths.py:taxonomy_root`, unchanged except the last step):

1. `PRLX_TAXONOMY_ROOT` env (or `PRLX_SOURCE_CALLEE_PACK` for the pack file directly)
2. a sibling `parallax-taxonomy/` checkout
3. **bundled fallback**: `engine/taxonomy/` (a verbatim copy of
   `parallax-taxonomy/signatures/`), so the vendored engine is self-contained with
   no env set.

## Usage

```python
from engine import engine, rules
report = engine.observe_report("/path/to/target")   # dict; report["observations"] holds the atoms
mode = rules.ast_mode()                              # "tree-sitter" or "regex-fallback"
```

Provenance and licensing: see `NOTICE` and `LICENSE` (Apache-2.0).

# unmask

Malicious Code Detection — *is this code doing something malicious, and can you
prove it?*

`unmask` is the **core** wheel: static/source analysis driven by a durable SQLite
work ledger and a phase graph, producing the deterministic MCD report (findings,
severity/confidence kept separate, disposition, evidence, disproof, verification,
coverage). It runs offline, executes no target code, and needs no decompilers.

Deep binary work (decompilation, binary triage, sandboxed tool execution, dynamic
verification) lives in the optional **`unmask-re`** wheel. When it is not
installed, binaries are reported as an explicit blind spot rather than silently
skipped.

```bash
pip install unmask          # persona 1: "is this suspicious?"
pip install unmask[review]  # + bounded agentic adjudication
pip install unmask-re       # persona 2: "rip these binaries apart"
```

```bash
mcd run ./suspicious-package
mcd tree ./suspicious-package
mcd report --run-id <id> --format html
```

The deterministic scanner is native to this package (`unmask/scanner/`) and its
taxonomy signature data is **vendored into this wheel**
(`unmask/taxonomy/vendored/`), so it runs self-contained with no external
`parallax-taxonomy` checkout.

The CLI command is `mcd`; the import package is `unmask`.

# unmask-re

Reverse-engineering skills for [`unmask`](../unmask) — the heavy half of MCD.

Installing this wheel registers a **skill-driven transform provider** under the
`unmask.providers` entry-point group. When a binary or obfuscated source artifact
is encountered, core hands it to the matching skill (decompile / deobfuscate /
unpack), the recovered source is rescanned, and the findings fold back in with
provenance. Capabilities are **prereq-gated**: a skill whose external tool (jadx,
ilspycmd, node, …) is missing advertises nothing, so the artifact routes to an
honest blind spot instead of a failed transform.

```bash
pip install unmask-re
```

## Vendored skills

The skills are copied from a sibling [rekit](../../rekit) checkout by
`scripts/sync_skills.py` (re-run to refresh; `--check` for CI staleness). Each is a
self-contained payload — vendored deps committed (webcrack node_modules for
`js-deobfuscate`, decompyle3 site for `pyc-decompile`) or a BYO-tool runner
(`jvm-decompile` needs jadx, `dotnet-decompile` needs ilspycmd).

| skill | capabilities | prereq |
|-------|-------------|--------|
| `unpack` | unpack-archive, extract-recursive | python3 (pure stdlib) |
| `js-deobfuscate` | deobfuscate-js, unpack-js-bundle | node ≥ 18 |
| `jvm-decompile` | decompile-jvm/apk/dex/jar | jadx (+ JRE) |
| `dotnet-decompile` | decompile-dotnet | ilspycmd (+ .NET) |
| `pyc-decompile` | decompile-python-bytecode | python3 (vendored decompyle3) |
| `bin-triage` | triage-binary, emit-atoms | python3 (pure stdlib) |
| `js-covert-scan` | detect-js-steganography/obfuscation/evasion | python3 |
| `py-covert-scan` | detect-py-obfuscation/evasion, steganography | python3 |
| `secrets-scan` | scan-secrets, detect-credentials | python3 |

Apache-2.0

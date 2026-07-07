# unmask-re

Reverse-engineering skills for [`unmask`](../unmask) — the heavy half of MCD.

Installing this wheel registers RE providers under the `unmask.providers`
entry-point group, so `unmask` core will attempt deep binary work (triage,
decompilation, sandboxed tool execution) instead of reporting binaries as a blind
spot.

```bash
pip install unmask-re
```

This is currently a **capability stub**: it advertises the RE capability set so the
core's plugin boundary and reporting can be exercised end to end. Real providers
(JADX/dex2jar, ILSpy, Ghidra/rizin, LIEF/capstone triage, OpenShell/subprocess
sandbox) land per the decompiler and sandbox milestones in `docs/design.md`.

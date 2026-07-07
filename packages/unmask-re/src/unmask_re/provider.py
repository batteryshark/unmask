"""RE provider registration (capability stub).

Core enumerates `unmask.providers` and reads `.id` / `.capabilities` off whatever
each entry point loads. This stub advertises the capability surface so the plugin
boundary, tool-doctor, and reporting work end to end before real decompilers land.

When a real provider is implemented it will also expose `run_tool` / `decompile`
methods behind the SandboxProvider protocol in docs/design.md; the graph's
scan-binary / decompile nodes will call those instead of leaving the work blocked.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class REProvider:
    id: str = "unmask-re.stub"
    capabilities: list[str] = field(default_factory=lambda: [
        "binary-triage",
        "decompile-dex",
        "decompile-apk",
        "decompile-jar",
        "decompile-dotnet",
        "decompile-native",
        "sandbox-exec",
    ])
    # Real implementations report which external tools actually resolved; the stub
    # reports none so a report can still distinguish skill-present-but-tools-absent.
    tools_available: list[str] = field(default_factory=list)


provider = REProvider()

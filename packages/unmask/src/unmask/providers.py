"""RE provider discovery — the plugin boundary between core and unmask-re.

Core never imports unmask-re directly. Instead it enumerates the
`unmask.providers` entry-point group at ResolveToolchain. Each registered
provider advertises capabilities (e.g. "decompile-dex", "binary-triage",
"sandbox-exec"). If nothing is registered, binaries are an honest blind spot:
core routes them to `blocked`/`needs_review` and the report says the deep
analysis was not attempted and how to enable it (`pip install unmask-re`).

Two independent "missing" layers compose here:
  - skill-layer missing  : no RE provider registered at all (this module)
  - tool-layer missing   : provider present but its external binary (jadx,
                           ghidra, ...) is absent  (unmask-re's tool doctor)
Both surface to the user identically: "this artifact was not deeply analysed."
"""

from __future__ import annotations

from dataclasses import dataclass, field
from importlib.metadata import entry_points

ENTRY_POINT_GROUP = "unmask.providers"

# Capabilities the core cares about when deciding whether a binary can be opened up.
BINARY_CAPABILITIES = {
    "binary-triage", "decompile", "decompile-dex", "decompile-apk",
    "decompile-jar", "decompile-dotnet", "decompile-native", "sandbox-exec",
    "emulate",
}


@dataclass
class ProviderInfo:
    id: str
    capabilities: list[str] = field(default_factory=list)
    source: str = ""
    error: str | None = None


@dataclass
class ToolchainStatus:
    providers: list[ProviderInfo] = field(default_factory=list)

    @property
    def available_capabilities(self) -> set[str]:
        caps: set[str] = set()
        for p in self.providers:
            if p.error is None:
                caps.update(p.capabilities)
        return caps

    @property
    def has_re(self) -> bool:
        return bool(self.available_capabilities & BINARY_CAPABILITIES)

    def to_report(self) -> dict:
        return {
            "reProvidersInstalled": self.has_re,
            "providers": [
                {"id": p.id, "capabilities": p.capabilities, "source": p.source,
                 "error": p.error}
                for p in self.providers
            ],
            "availableCapabilities": sorted(self.available_capabilities),
            "hint": None if self.has_re else
                    "Install `unmask-re` to decompile and triage binaries; without it "
                    "binary artifacts are reported as an unanalysed blind spot.",
        }


def discover_providers() -> ToolchainStatus:
    """Enumerate registered RE providers. Never raises — a broken provider is
    recorded with its error, not crashed on."""
    status = ToolchainStatus()
    try:
        eps = entry_points(group=ENTRY_POINT_GROUP)
    except TypeError:  # pragma: no cover - very old importlib.metadata
        eps = entry_points().get(ENTRY_POINT_GROUP, [])  # type: ignore[attr-defined]
    for ep in eps:
        try:
            obj = ep.load()
            caps = list(getattr(obj, "capabilities", []) or [])
            pid = getattr(obj, "id", ep.name)
            status.providers.append(ProviderInfo(id=pid, capabilities=caps, source=ep.value))
        except Exception as exc:  # pragma: no cover
            status.providers.append(
                ProviderInfo(id=ep.name, source=ep.value, error=f"{type(exc).__name__}: {exc}"))
    return status

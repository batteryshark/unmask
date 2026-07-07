"""Container reveal — unpack packed targets and scan the revealed code."""

from __future__ import annotations

import json
import struct
import zipfile
from pathlib import Path


def _build_asar(files: dict[str, bytes], out_path: Path) -> Path:
    """Minimal Electron .asar (Chromium Pickle framing), flat single-directory."""
    payload = bytearray()
    entries: dict[str, dict] = {}
    for name, content in files.items():
        entries[name] = {"offset": str(len(payload)), "size": len(content)}
        payload += content
    header_json = json.dumps({"files": entries}).encode("utf-8")
    padded = header_json + b"\x00" * ((-len(header_json)) % 4)
    payload_size = 4 + len(padded)
    header_size = payload_size + 4
    framing = struct.pack("<IIII", 4, header_size, payload_size, len(header_json))
    out_path.write_bytes(framing + padded + bytes(payload))
    return out_path


# base64-decode-and-eval — BP-OBFEXEC once the JS is revealed.
_MAL_JS = (b'const p = "ZWNobyBoaQ==";\n'
           b'function decode(s) { return Buffer.from(s, "base64").toString(); }\n'
           b'eval(decode(p));\n')


def _bundle_with_asar(root: Path) -> Path:
    (root / "Resources").mkdir(parents=True)
    _build_asar({"index.js": _MAL_JS}, root / "Resources" / "app.asar")
    return root


def test_reveal_asar_exposes_hidden_js(tmp_path):
    from unmask.scanner.compose import compose_mcd
    from unmask.scanner.observe import observe

    tgt = _bundle_with_asar(tmp_path / "tgt")
    obs, inv = observe(str(tgt), reveal_dir=str(tmp_path / "rev"))
    atoms = {o.atom for o in obs}
    assert "LOAD.EVAL" in atoms and "XFRM.ENCODE" in atoms
    assert "BP-OBFEXEC" in {f.get("composition") for f in compose_mcd(obs, inv)}


def test_opaque_container_finds_nothing_without_reveal(tmp_path):
    from unmask.scanner.observe import observe

    tgt = _bundle_with_asar(tmp_path / "tgt")
    obs, _ = observe(str(tgt))  # no reveal_dir → the asar stays opaque
    assert "LOAD.EVAL" not in {o.atom for o in obs}


def test_reveal_recurses_zip_wrapped_asar(tmp_path):
    from unmask.scanner.observe import observe

    stage = tmp_path / "stage"
    stage.mkdir()
    asar = _build_asar({"index.js": _MAL_JS}, stage / "app.asar")
    tgt = tmp_path / "tgt"
    tgt.mkdir()
    with zipfile.ZipFile(tgt / "app.zip", "w") as zf:
        zf.write(asar, arcname="app.asar")

    obs, _ = observe(str(tgt), reveal_dir=str(tmp_path / "rev"))  # zip -> asar -> js
    assert "LOAD.EVAL" in {o.atom for o in obs}


def test_zip_slip_is_blocked(tmp_path):
    from unmask.scanner.observe.containers import reveal

    tgt = tmp_path / "tgt"
    tgt.mkdir()
    with zipfile.ZipFile(tgt / "evil.zip", "w") as zf:
        zf.writestr("../../escape.txt", "pwned")
    reveal(str(tgt), str(tmp_path / "rev"))
    assert not (tmp_path / "escape.txt").exists()
    assert not (tmp_path.parent / "escape.txt").exists()


def test_mcd_run_reveals_packed_malware(tmp_path):
    from unmask import MCDConfig, run_mcd

    tgt = _bundle_with_asar(tmp_path / "tgt")
    result = run_mcd(str(tgt), MCDConfig(storage_root=str(tmp_path / ".mcd")))
    report = json.loads(Path(result.report_paths["json"]).read_text())
    assert "BP-OBFEXEC" in (report["summary"].get("compositions") or [])
    assert result.disposition in {"review", "quarantine"}

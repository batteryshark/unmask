"""Shared assessment helpers: severity/confidence ranking, correlation loci, and
the stated contract/coverage notes. Ported from `mcd_lens.assess.common`."""

from __future__ import annotations

import re

from unmask.scanner.compose.common import _SEV_RANK

ASSESSMENT_VERSION = "0.1.0"
MCD_LENS = "mcd"
SCANNER = "unmask"
SCANNER_VERSION = "0.0.1"

# Authoritative list of implemented BP-* compositions (order matters for the note).
MCD_COMPOSITIONS = [
    "BP-SUPPLY", "BP-TYPOSQUAT", "BP-DROPPER", "BP-CREDTHEFT", "BP-OBFEXEC",
    "BP-BACKDOOR", "BP-EXFIL", "BP-RANSOM", "BP-TIMEBOMB", "BP-MINER",
    "BP-ROOTKIT", "BP-WORM", "BP-TROJAN", "BP-AGENTMANIP", "BP-LATERAL", "BP-MITM",
]

_URL_RE = re.compile(r"https?://([^/\s:\"']+)", re.IGNORECASE)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_COMMON_HOSTS = {
    "registry.npmjs.org", "pypi.org", "files.pythonhosted.org", "crates.io",
    "github.com", "raw.githubusercontent.com", "localhost", "127.0.0.1", "0.0.0.0",
    "example.com",
}

_COOCCUR_INSIGHTS = [
    ({"BP-SUPPLY", "BP-DROPPER"},
     "the package's install step runs code that downloads and executes a remote payload, so the "
     "dropper fires at install time, before any explicit use"),
    ({"BP-SUPPLY", "BP-OBFEXEC"},
     "the install step runs obfuscated or decoded code, so the payload executes at install time "
     "and resists casual reading"),
    ({"BP-SUPPLY", "BP-CREDTHEFT"}, "credential access runs as part of the install step"),
    ({"BP-DROPPER", "BP-CREDTHEFT"},
     "the same locus both fetches or executes remote content and reads credential material, the "
     "fetch-then-exfiltrate shape"),
    ({"BP-TYPOSQUAT", "BP-SUPPLY"},
     "a name resembling a popular package also carries an install-time payload, the slopsquat-"
     "with-payload shape"),
    ({"BP-DROPPER", "BP-OBFEXEC"},
     "remote content is fetched and executed through an obfuscation or decode step"),
    ({"BP-BACKDOOR", "BP-ROOTKIT"},
     "remote access or bypass behavior is paired with system-level concealment"),
    ({"BP-EXFIL", "BP-CREDTHEFT"},
     "general sensitive-data collection and credential-specific theft signals co-occur"),
    ({"BP-TIMEBOMB", "BP-TROJAN"}, "a disguised payload is also gated by time or environment"),
    ({"BP-WORM", "BP-LATERAL"}, "propagation and internal movement signals co-occur"),
    ({"BP-MITM", "BP-CREDTHEFT"},
     "traffic interception or trust weakening appears near credential theft signals"),
    ({"BP-AGENTMANIP", "BP-EXFIL"}, "agent-steering content is paired with a data-egress surface"),
]

_CONTRACT_NOTE = (
    "This is an MCD assessment: a projection of a scan onto the malicious-code "
    "question. It recommends a disposition (a next-action), not a maliciousness "
    "verdict. Severity (how bad if real) is reported separately from confidence (how "
    "sure), and every finding states what would disprove it. The rules own coverage "
    "and the mcd lens owns judgment; this view composes them and does not re-analyze."
)

_IMPLEMENTATION_NOTE = (
    "Implemented MCD composition coverage: " + ", ".join(MCD_COMPOSITIONS)
    + ". CLEAR means no findings matched this implemented set under the current static methods; "
      "it is not a full safety verdict and does not include runtime behavior or unavailable enrichment."
)


def _rank(sev):
    return _SEV_RANK.get(sev or "informational", 0)


def _max_severity(findings):
    sevs = [f.get("severity") for f in findings if f.get("severity")]
    return max(sevs, key=_rank) if sevs else None


def _max_confidence(findings):
    cs = [f.get("confidence") for f in findings if isinstance(f.get("confidence"), (int, float))]
    return max(cs) if cs else None


def _confidence_label(c):
    if c is None:
        return None
    if c >= 0.75:
        return "high"
    if c >= 0.45:
        return "medium"
    return "low"


def _signal_type(o):
    if (o.get("method") or "") == "binary-strings":
        return "binary"
    if (o.get("atom") or "").startswith("PKGM"):
        return "package"
    return "source"


def _indicators(o):
    ev = o.get("evidence") or {}
    text = " ".join([ev.get("summary") or "", ev.get("matchedText") or ""])
    out = set()
    for h in _URL_RE.findall(text):
        h = h.lower()
        if h not in _COMMON_HOSTS:
            out.add(h)
    for ip in _IP_RE.findall(text):
        if ip not in _COMMON_HOSTS:
            out.add(ip)
    return out


def _finding_loci(finding, obs_by_id):
    files, inds = set(), set()
    for oid in finding.get("evidence", []):
        o = obs_by_id.get(oid)
        if not o:
            continue
        p = (o.get("location") or {}).get("path")
        if p:
            files.add(p)
        inds |= _indicators(o)
    return files, inds

"""Shared assessment helpers: constants, severity/confidence ranking, indicators,
and finding loci -- used by correlate / disposition / render / build."""

from __future__ import annotations

import html
import json
import re
import uuid
from datetime import datetime, timezone

from engine import __version__, SCANNER
from engine import runtime as runtime_mod
from engine.interpret.common import _SEV_RANK
from mcd_lens.readings import MCD_COMPOSITIONS

ASSESSMENT_VERSION = "0.1.0"

# The lens whose findings ARE the malicious-code question. Supply-chain shapes
# (typosquat / undeclared / install hook) and binary-strings evidence all surface
# as mcd-lens findings, so this single filter captures source + supply + binary.
MCD_LENS = "mcd"

# When scanning fresh, run the full lens set so the assessment can honestly say
# whether OTHER lenses fired (an MCP server that manipulates agents has 0 mcd
# findings but is still not "safe"). The mcd findings drive the assessment; the
# rest become a "related signals" pointer to the risk map.
DEFAULT_SCAN_LENSES = ["mcd", "decisions", "capability", "agentic", "curiosity"]

_URL_RE = re.compile(r"https?://([^/\s:\"']+)", re.IGNORECASE)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Hosts common enough that sharing one is not evidence of a connection. Keeps the
# correlator from merging unrelated findings just because both touch a registry.
_COMMON_HOSTS = {
    "registry.npmjs.org", "pypi.org", "files.pythonhosted.org", "crates.io",
    "github.com", "raw.githubusercontent.com", "localhost", "127.0.0.1", "0.0.0.0",
    "example.com",
}

# Stated co-occurrence insights: when these compositions share a locus, what the
# combination means. Declared up front, not inferred per run.
_COOCCUR_INSIGHTS = [
    ({"BP-SUPPLY", "BP-DROPPER"},
     "the package's install step runs code that downloads and executes a remote payload, so the "
     "dropper fires at install time, before any explicit use"),
    ({"BP-SUPPLY", "BP-OBFEXEC"},
     "the install step runs obfuscated or decoded code, so the payload executes at install time "
     "and resists casual reading"),
    ({"BP-SUPPLY", "BP-CREDTHEFT"},
     "credential access runs as part of the install step"),
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
    ({"BP-TIMEBOMB", "BP-TROJAN"},
     "a disguised payload is also gated by time or environment"),
    ({"BP-WORM", "BP-LATERAL"},
     "propagation and internal movement signals co-occur"),
    ({"BP-MITM", "BP-CREDTHEFT"},
     "traffic interception or trust weakening appears near credential theft signals"),
    ({"BP-AGENTMANIP", "BP-EXFIL"},
     "agent-steering content is paired with a data-egress surface"),
]

# Plain-language "how to read this" guide, keyed by composition. Rendered once per
# report in a single section near the bottom, so a report with several findings of
# the same type explains that type once instead of repeating it inline. Only the
# axis note plus entries for composition types actually present are shown; entirely
# deterministic, like the rest of the engine.
_READING_AXES = (
    "Two independent axes. Severity is how bad this would be if it is real; confidence "
    "is how sure the engine is that it is real. A finding can be high severity and low "
    "confidence at once. Many findings flag a co-occurrence: the parts of a chain "
    "located in the same scope, not a value proven to flow from one step to the next. "
    'When intra-file taint did not connect the steps, the claim says "Dataflow: not '
    'proven" and confidence stays at the co-occurrence level; a proven trace raises it. '
    'Read a finding\'s priority from its severity and its certainty from its confidence, '
    'then use its "what would disprove this" and "verify next" lines to settle it.'
)

_READING_GUIDE = {
    "BP-SUPPLY": ("Install-time payload path",
        "A package install hook runs network, shell, or decode-and-execute behavior "
        "before any of your code is invoked. Install-time execution runs before you can "
        "review or sandbox it, which is why it is high severity even when the payload "
        "itself is not yet proven malicious."),
    "BP-TYPOSQUAT": ("Typosquat / slopsquat name",
        "The package name is a near-miss of a popular one. Name similarity alone is a "
        "local signal (medium on its own, high when the package also ships a payload); "
        "confirming a squat rather than an owned variant needs the registry, which this "
        "offline engine cannot reach."),
    "BP-DROPPER": ("Download-and-execute (dropper) path",
        "One file fetches remote content, writes it to disk, and executes or loads it: "
        "the canonical dropper. The payload is whatever the server returns at runtime, "
        "which static analysis cannot see, so confidence turns on whether the written "
        "artifact is actually executed and what is delivered."),
    "BP-CREDTHEFT": ("Credential access + egress path",
        "Credential-reading code and an outbound network channel share one file: the "
        "collect-and-transmit shape of credential theft. Reading a secret and making a "
        "request is also what most legitimate API clients do, so the finding is only as "
        "strong as its two open questions: does the secret flow into the request, and is "
        "the destination the credential's own service."),
    "BP-OBFEXEC": ("Obfuscated code execution (decode-and-execute)",
        "Code decodes or decrypts a blob and then executes it, so the payload is hidden "
        "from source review until it runs. Severity is high because the executed content "
        "is unknown until then; decoding the blob is what settles it."),
    "BP-BACKDOOR": ("Backdoor",
        "A command channel plus execution, or embedded bypass material near access-control or "
        "privileged behavior. The key question is whether the channel or credential is authorized "
        "and documented; static source can show the shape but not permission."),
    "BP-EXFIL": ("Data exfiltration",
        "Host, process, clipboard, sensitive-file, or other collected data appears next to an "
        "outbound channel. It is broader than credential theft and is settled by tracing whether "
        "the collected data reaches the request."),
    "BP-RANSOM": ("Ransomware",
        "File enumeration plus encryption and file mutation is the structural ransomware shape. "
        "Legitimate backup and encryption tools can look similar, so path flow and stated purpose matter."),
    "BP-TIMEBOMB": ("Logic bomb / time bomb",
        "Time or environment checks appear near a payload. The trigger may be benign scheduling or "
        "CI gating, so review both branches and run under gated conditions."),
    "BP-MINER": ("Resource hijacking",
        "Mining or proof-of-work markers appear with network or payout indicators. Legitimate miners "
        "and benchmarks should say so plainly and only run on explicit user action."),
    "BP-ROOTKIT": ("Rootkit / concealment",
        "System-level hooks, kernel/module loading, injection, or privileged memory access appears "
        "with concealment, persistence, or security-control tampering."),
    "BP-WORM": ("Worm / propagation",
        "Discovery of systems or accounts appears with network channels and a delivery/action surface. "
        "The propagation question is whether discovered targets feed the action."),
    "BP-TROJAN": ("Trojan / disguised payload",
        "The advertised purpose does not explain concealed high-risk behavior. This is a mismatch "
        "finding: documentation can disprove it, but silence raises concern."),
    "BP-AGENTMANIP": ("Agent manipulation",
        "Agent-facing or hidden instructions sit next to a payload-capable surface. The MCD question is "
        "whether an agent can be steered into execution, exfiltration, credential access, or persistence."),
    "BP-LATERAL": ("Lateral movement",
        "Internal discovery, credentials or privilege, and remote/local action co-occur. It may be admin "
        "tooling, but the key question is whether authority is used against newly discovered targets."),
    "BP-MITM": ("Traffic interception / MITM setup",
        "Trust verification is weakened or traffic routing is manipulated near network handling. "
        "Development proxies and test TLS bypasses are common disproofs."),
}


def _reading_entries(findings):
    """The (code, title, guide) entries to explain: composition types present in
    `findings`, in guide order, deduped. Empty when no listed composition appears."""
    present = {f.get("composition") for f in findings if f.get("composition")}
    return [(code, title, guide)
            for code, (title, guide) in _READING_GUIDE.items() if code in present]


_CONTRACT_NOTE = (
    "This is a Parallax MCD assessment: a projection of a scan onto the malicious-"
    "code question. It recommends a disposition (a next-action), not a maliciousness "
    "verdict. Severity (how bad if real) is reported separately from confidence (how "
    "sure), and every finding states what would disprove it. The rules own coverage "
    "and the mcd lens owns judgment; this view composes them and does not re-analyze."
)

_IMPLEMENTATION_NOTE = (
    "Implemented MCD composition coverage in this engine: "
    + ", ".join(MCD_COMPOSITIONS)
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
    """Which signal a single observation came from: binary / package / source."""
    if (o.get("method") or "") == "binary-strings":
        return "binary"
    if (o.get("atom") or "").startswith("PKGM"):
        return "package"
    return "source"


def _indicators(o):
    """Specific network indicators (hosts from URLs, IPs) in an observation, minus
    common hosts that would cause benign over-merging."""
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
    """The files and indicators a finding's evidence touches (its linking keys)."""
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



__all__ = ['ASSESSMENT_VERSION', 'MCD_LENS', 'DEFAULT_SCAN_LENSES', '_URL_RE', '_IP_RE',
           '_COMMON_HOSTS', '_COOCCUR_INSIGHTS', '_READING_AXES', '_READING_GUIDE',
           '_reading_entries', '_CONTRACT_NOTE', '_IMPLEMENTATION_NOTE', '_rank',
           '_max_severity', '_max_confidence', '_confidence_label', '_signal_type',
           '_indicators', '_finding_loci', '__version__', 'SCANNER', 'runtime_mod',
           '_SEV_RANK', 'MCD_COMPOSITIONS', 'html', 'json', 're', 'uuid', 'datetime', 'timezone']

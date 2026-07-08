"""Contextual confidence attenuators — the deterministic false-positive control.

`compose_mcd` is judgment-free composition: it fires a BP-* finding whenever the
atoms for a malicious-code shape co-occur. That is the right default — better to
flag and let review/attenuation resolve than to silently miss a shape. But it
means a documented, maintainer-controlled `curl … astral.sh/uv/install.sh | sh`
in a CI workflow fires BP-DROPPER at the same confidence as a real dropper.

This module is the deterministic, offline layer that resolves those well-known
benign idioms WITHOUT removing the finding (review can still escalate a
typosquat of `astral.sh`). It runs AFTER compose as a separate pass so:

  * `compose_mcd` stays the judgment-free oracle (the parity tests pin it); and
  * every attenuation records the original confidence, the factor applied, and a
    human-readable reason, so the report shows exactly what was adjusted and why.

Two independent attenuators compose:

  1. **documented-installer idiom** — the cited evidence matches a known-good,
     maintainer-controlled install script (uv/Ruff/docker/nvm/rustup/…). Strong
     attenuation (factor ~0.5). The finding stays so review can catch a
     typosquat of the host, but it drops below the quarantine bar.
  2. **CI / install-script context** — the evidence path is a CI workflow,
     Dockerfile, or install/setup script where `curl|sh` is an expected idiom.
     Moderate attenuation (factor ~0.7), applied independently.

When both fire (a documented installer in a CI file) the factors stack, giving
the strongest honest attenuation for the most common false-positive shape.
Attenuation NEVER removes a finding and NEVER touches the `amplifiers`/proof
depth — only confidence. A false-negative risk note is always attached so a
reviewer can see what the attenuation could hide.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from unmask.scanner.compose.common import confidence_label

# A confidence floor below which attenuation will not push a finding — keeps a
# residual signal so a "documented installer" finding is still visible, just not
# quarantine-driving. Findings already at/below the floor are left alone.
_CONF_FLOOR = 0.2

# Documented, maintainer-controlled installer idioms. Each entry is a regex
# matched (case-insensitive, DOTALL) against the concatenation of the cited
# observations' matched text. A match means "this is the official install
# pattern for <name>." These are high-specificity anchors (host + path), not
# generic `curl|sh` — a generic pipe-to-shell does NOT match here.
#
# Keep this conservative: only idioms that are (a) the documented install
# method, (b) maintainer-controlled hosts, and (c) widely used. Anything
# ambiguous is left for review.
_DOCUMENTED_INSTALLERS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("uv (Astral)",
     re.compile(r"astral\.sh/(?:uv|ruff)/install", re.I)),
    ("Docker",
     re.compile(r"get\.docker\.com(?:/rootless)?(?:\s|$|['\"])", re.I)),
    ("nvm",
     re.compile(r"raw\.githubusercontent\.com/nvm-sh/nvm|nvm\.sh", re.I)),
    ("fnm",
     re.compile(r"fnm\.vercel\.app/install", re.I)),
    ("rustup",
     re.compile(r"sh\.rustup\.rs|rustup\.rs", re.I)),
    ("pyenv",
     re.compile(r"pyenv\.run", re.I)),
    ("Deno",
     re.compile(r"deno\.land/install", re.I)),
    ("Bun",
     re.compile(r"bun\.sh/install", re.I)),
    ("Homebrew",
     re.compile(r"raw\.githubusercontent\.com/Homebrew/install/.*install\.sh", re.I)),
    ("pnpm (Corepack)",
     re.compile(r"corepack(?:\.js\.org)?(?:/install| enable pnpm)", re.I)),
    ("Volta",
     re.compile(r"volta\.sh", re.I)),
    ("Go",
     re.compile(r"go\.dev/dl/|golang\.org/dl/", re.I)),
    ("yarn (Corepack)",
     re.compile(r"corepack enable yarn", re.I)),
)

# CI / install-script path contexts. A finding whose cited evidence lives in one
# of these paths is in a context where fetch-and-execute (curl|sh) is an expected
# idiom rather than a runtime behavior of the shipped code. Matched against the
# normalized (forward-slash) evidence path.
_CI_CONTEXT_RE = re.compile(
    r"(^|/)"
    r"(?:\.github/workflows/[^/]+\.(?:yml|yaml)"      # GitHub Actions workflows
    r"|\.github/actions/[^/]+/action\.(?:yml|yaml)"    # GitHub composite actions
    r"|action\.(?:yml|yaml)"                           # any GitHub Action definition
    r"|\.gitlab-ci\.(?:yml|yaml)"                      # GitLab CI
    r"|\.circleci/config\.(?:yml|yaml)"                # CircleCI
    r"|\.travis\.(?:yml|yaml)"                         # Travis
    r"|azure-pipelines\.(?:yml|yaml)"                  # Azure Pipelines
    r"|Jenkinsfile(?:\..+)?)"                          # Jenkins
    r"(?:$|/)",
    re.I,
)
# Standalone install/setup/bootstrap scripts (scripts/install.sh, setup.py-as-installer,
# bootstrap, dev.sh). Matched against the basename + immediate parent dir.
_INSTALL_SCRIPT_RE = re.compile(
    r"(?:^|/)"
    r"(?:scripts|script|bin|toolbox|hack)/"            # under a scripts/-like dir
    r"(?:install|setup|bootstrap|provision|dev|init|get)[._-]?\w*$",
    re.I,
)
# Dockerfiles bake curl|sh into images routinely.
_DOCKERFILE_RE = re.compile(r"(?:^|/)Dockerfile(?:\..+)?$", re.I)

# Documentation contexts. Markdown / README / INSTALL / docs/ render fetch-and-execute
# as INSTALL INSTRUCTIONS to display, not code paths to execute — the single biggest
# benign source of BP-DROPPER false positives (every project's README shows
# `curl … | sh` as its install command). Markdown is never executed by the runtime, so
# documentation attenuation is stronger than CI attenuation.
_DOC_CONTEXT_RE = re.compile(
    r"(?:^|/)"
    r"(?:README[^/]*"                                  # README, README.md, README.ar.md
    r"|INSTALL[^/]*"                                   # INSTALL, INSTALL.md
    r"|CHANGELOG[^/]*"                                 # CHANGELOG
    r"|CONTRIBUTING[^/]*"                              # CONTRIBUTING
    r"|HISTORY[^/]*"                                   # HISTORY
    r"|UPGRADING[^/]*"                                 # UPGRADING
    r"|docs?/[^/]+"                                    # docs/guide.md, doc/install.md
    r"|\.md$|\.markdown$|\.mdx$)",                     # any markdown by extension
    re.I,
)
# Download / install UI pages — a React/Vue/HTML route whose path marks it as a
# download or install page renders `curl|sh` as the install command to DISPLAY
# (a copy-to-clipboard affordance), not a code path the app executes. Matched
# against path segments under common UI-route directories.
_DOWNLOAD_UI_RE = re.compile(
    r"(?:^|/)"
    r"(?:routes|pages|views|components|screens|templates)/"  # a UI-route/component dir
    r"(?:[^/]*download[^/]*|[^/]*install[^/]*)",             # a download/install-named route
    re.I,
)

# A literal remote-exec string (the BP-DROPPER "direct remote exec" branch): the
# evidence is a text-matched `curl|sh` / `wget|sh` / `iex(irm…)` literal, NOT a
# dataflow-proven source→sink path. Literal install-command strings appear in
# READMEs, download pages, CI, and install scripts of nearly every project, so a
# purely textual match sitting ABOVE the quarantine threshold is the design flaw
# behind the worst false-positive class. This brings the unproven literal variant
# just below the bar; dataflow-proven droppers (amplifier "Proof depth:") are
# untouched and stay at 0.7–0.9.
_LITERAL_REMOTE_EXEC_RE = re.compile(
    r"(?:curl|wget|iex\s*\(\s*irm|invoke-webrequest|invoke-expression)"
    r".{0,40}(?:\|\s*(?:sh|bash|zsh|powershell|pwsh)|;\s*sh\b)",
    re.I | re.DOTALL,
)
_MARKDOWN_LANGS = frozenset({"markdown", "md", "mdx", "asciidoc", "rst", "textile"})

# Compositions most prone to documented-installer false positives. Restricting
# the installer-idiom attenuator to these keeps it from softening unrelated
# shapes (e.g. BP-CREDTHEFT) that happen to cite the same file.
_INSTALLER_PRONE = frozenset({"BP-DROPPER", "BP-SUPPLY", "BP-OBFEXEC"})
# Documentation attenuation only makes sense for fetch-and-execute / install-time
# shapes — a credential read documented in a README still matters.
_DOC_PRONE = frozenset({"BP-DROPPER", "BP-SUPPLY", "BP-OBFEXEC"})


@dataclass(frozen=True)
class _Attenuation:
    reason: str
    factor: float          # multiplicative; applied to current confidence
    fnr_note: str          # false-negative risk — what this could hide


_INSTALLED_IDIOM = _Attenuation(
    reason="Cited evidence matches the documented, maintainer-controlled install idiom for {name}.",
    factor=0.5,
    fnr_note="A typosquat or compromised host for {name} would still be malicious; review should "
             "confirm the host spelling and TLS against the project's official docs.",
)
_CI_CONTEXT = _Attenuation(
    reason="Evidence is in a CI workflow / Dockerfile / install script — a context where "
           "fetch-and-execute is an expected idiom, not a runtime behavior of shipped code.",
    factor=0.7,
    fnr_note="A malicious CI step can still exfiltrate secrets or backdoor builds; this only "
             "removes the auto-quarantine push, it does not clear the finding.",
)
_DOC_CONTEXT = _Attenuation(
    reason="Evidence is in a documentation file (README/INSTALL/markdown/docs) — fetch-and-execute "
           "appears here as an install instruction to display, not a code path the runtime executes.",
    factor=0.4,
    fnr_note="Documentation could still describe a genuinely malicious command, or a markdown-driven "
             "tool could eval fenced code; review should confirm the command is the standard install "
             "idiom and not an exfil/decode payload.",
)
_DOWNLOAD_UI = _Attenuation(
    reason="Evidence is in a download/install UI route (routes/download, pages/install) — the "
           "fetch-and-execute string is rendered as the install command to display/copy, not executed "
           "by the application at runtime.",
    factor=0.6,
    fnr_note="A download page could still trigger the command via a copy-to-run affordance or a "
             "postinstall hook; review should confirm the string is display-only.",
)
_UNPROVEN_DROPPER = _Attenuation(
    reason="Dropper path (fetch + write + execute co-occurrence) with NO dataflow-proven "
           "source→sink connection. Same-file co-occurrence of these atoms is the most common "
           "false-positive shape (downloaders, codegens, caches, build tools all fetch+write+run); "
           "without a proven value path it sits below the quarantine bar.",
    factor=0.95,  # 0.65 -> ~0.62; just below quarantine, stays a visible review item
    fnr_note="A real dropper whose fetch→write→exec steps are connected only at runtime (not "
             "intra-file taint) would be attenuated; the dataflow-proven branch (0.9) catches the "
             "connected-path variant and is NOT attenuated.",
)
_DIRECT_EXEC_IN_SOURCE = _Attenuation(
    reason="Direct-remote-exec literal (curl|sh / iex) in non-shell SOURCE code. The string must be "
           "passed to a shell/eval at runtime for it to execute; the atoms alone prove the string is "
           "present, not that it reaches an executor. (A curl|sh in an actual .sh script IS the "
           "execution and is not attenuated.)",
    factor=0.9,  # 0.68 -> ~0.61; just below quarantine, stays a visible review item
    fnr_note="A real dropper that builds the curl|sh string in source and passes it to exec() would "
             "be attenuated; the dataflow-proven branch (0.7–0.9) catches the connected-path variant.",
)
# Marker the compose layer puts on dropper-path findings whose source→sink was NOT
# proven by intra-file taint (only same-file co-occurrence). Distinguishes the
# unproven co-occurrence variant (attenuated) from the literal direct-remote-exec
# variant (left at full confidence — a curl|sh to an unknown host is genuinely
# suspicious and should keep driving quarantine until a benign signal attenuates it).
_UNPROVEN_OCCURRENCE_MARKER = "same-file co-occurrence"
_PROOF_DEPTH_MARKER = "proof depth:"  # only dataflow-proven findings carry this amplifier
# Shell-script languages: a curl|sh literal here IS execution (not attenuated by the
# direct-exec-in-source rule). Everything else is source where the string must be
# routed to an executor.
_SHELL_LANGS = frozenset({"shell", "bash", "sh", "zsh", "fish", "powershell", "batch", "dos"})


def _obs_text(obs: dict) -> str:
    """Lowercased concatenation of an observation's evidence text for regex matching."""
    ev = obs.get("evidence") or {}
    parts = [obs.get("summary") or "", ev.get("matchedText") or "", ev.get("summary") or ""]
    return " ".join(str(p) for p in parts if p).lower()


def _evidence_paths(findings_obs: list[dict]) -> list[str]:
    paths = []
    for o in findings_obs:
        loc = o.get("location") or {}
        p = loc.get("path")
        if p:
            paths.append(str(p).replace("\\", "/"))
    return paths


def _match_installer(text: str) -> str | None:
    for name, pat in _DOCUMENTED_INSTALLERS:
        if pat.search(text):
            return name
    return None


def _is_ci_context(paths: list[str]) -> bool:
    return any(_CI_CONTEXT_RE.search(p) or _INSTALL_SCRIPT_RE.search(p) or _DOCKERFILE_RE.search(p)
               for p in paths)


def _apply(finding: dict, attenuation: _Attenuation, **fmt) -> None:
    """Multiply the finding's confidence by ``factor`` (floored), record the reason
    and false-negative-risk note. The original confidence is preserved on the
    finding so the report can show what was adjusted."""
    reason = attenuation.reason.format(**fmt)
    fnr = attenuation.fnr_note.format(**fmt)
    orig = finding.get("confidence")
    if orig is None:
        return
    if "originalConfidence" not in finding:
        finding["originalConfidence"] = round(float(orig), 2)
    new = max(_CONF_FLOOR, float(orig) * attenuation.factor)
    # Stack multiplicatively if attenuating again (installer × CI).
    finding["confidence"] = round(min(new, finding.get("confidence", new)), 2)
    finding["confidenceLabel"] = confidence_label(finding["confidence"])
    atts = list(finding.get("attenuators") or [])
    if reason not in atts:
        atts.append(reason)
    finding["attenuators"] = atts
    fnrs = list(finding.get("attenuatorFalseNegativeRisk") or [])
    if fnr not in fnrs:
        fnrs.append(fnr)
    finding["attenuatorFalseNegativeRisk"] = fnrs


def _is_doc_context(paths: list[str], langs_by_path: dict[str, str]) -> bool:
    for p in paths:
        if _DOC_CONTEXT_RE.search(p):
            return True
        if langs_by_path.get(p) in _MARKDOWN_LANGS:
            return True
    return False


def apply_contextual_attenuators(findings: list[dict], observations: list, inv=None) -> list[dict]:
    """Return ``findings`` with contextual attenuation applied in place.

    ``observations`` is the raw Observation stream (objects with ``.id``, ``.path``,
    ``.evidence``) — the same objects compose saw, so the evidence we attenuate on
    is exactly what the finding cites. ``inv`` (optional) lets us resolve each
    cited path's language precisely (markdown detection) via the inventory's
    FileEntry.language. Safe to call with dict observations too (the graph
    re-records from dicts after transforms).
    """
    if not findings:
        return findings
    # rel path -> language, from the inventory, for precise markdown detection.
    langs_by_path: dict[str, str] = {}
    if inv is not None:
        for fe in getattr(inv, "files", []) or []:
            rel = str(getattr(fe, "rel", "") or "").replace("\\", "/")
            lang = str(getattr(fe, "language", "") or "").lower() or None
            if rel and lang:
                langs_by_path[rel] = lang
    # Build an id -> {path, text} index once. Tolerate Observation objects and dicts.
    obs_index: dict[str, dict] = {}
    for o in observations:
        oid = getattr(o, "id", None) or (o.get("id") if isinstance(o, dict) else None)
        if not oid:
            continue
        if isinstance(o, dict):
            path = ((o.get("location") or {}).get("path") or "").replace("\\", "/")
            text = _obs_text(o)
        else:
            path = str(getattr(o, "path", "") or "").replace("\\", "/")
            ev = getattr(o, "evidence", "")
            text = (str(ev or "")).lower()
        obs_index[oid] = {"path": path, "text": text}

    for f in findings:
        ev_ids = f.get("evidence") or []
        cited = [obs_index[i] for i in ev_ids if i in obs_index]
        if not cited:
            continue
        text = " ".join(c["text"] for c in cited)
        paths = [c["path"] for c in cited if c["path"]]

        # 1. Documented-installer idiom — only for the compositions prone to this FP.
        if f.get("composition") in _INSTALLER_PRONE:
            name = _match_installer(text)
            if name:
                _apply(f, _INSTALLED_IDIOM, name=name)

        # 2. Documentation context (README/markdown/docs) — markdown is never executed,
        #    so this is the strongest honest attenuator for the most common FP. Only the
        #    fetch-and-execute / install shapes are softened; BP-CREDTHEFT in a README
        #    still matters.
        if f.get("composition") in _DOC_PRONE and _is_doc_context(paths, langs_by_path):
            _apply(f, _DOC_CONTEXT)

        # 3. Download / install UI route — the curl|sh string is rendered to display.
        if f.get("composition") in _DOC_PRONE and any(_DOWNLOAD_UI_RE.search(p) for p in paths):
            _apply(f, _DOWNLOAD_UI)

        # 4. CI / install-script / Dockerfile context — independent of composition.
        if _is_ci_context(paths):
            _apply(f, _CI_CONTEXT)

        # 5. Unproven dropper PATH (fetch+write+exec co-occurrence, no dataflow proof).
        #    Identified by the compose layer's "same-file co-occurrence" proof marker on
        #    the attenuators — NOT the literal direct-remote-exec variant (a curl|sh to an
        #    unknown host stays at full confidence; only positive benign signals in
        #    steps 1–4 soften that one). The co-occurrence variant sits AT the quarantine
        #    threshold by default, so a tiny attenuation drops it just below the bar where
        #    it belongs as a review item, not an auto-quarantine.
        if f.get("composition") == "BP-DROPPER":
            att_text = " ".join(str(a or "").lower() for a in (f.get("attenuators") or []))
            amps_text = " ".join(str(a or "").lower() for a in (f.get("amplifiers") or []))
            has_co_occurrence = _UNPROVEN_OCCURRENCE_MARKER in att_text
            has_proof = _PROOF_DEPTH_MARKER in amps_text
            if has_co_occurrence and not has_proof:
                _apply(f, _UNPROVEN_DROPPER)
            elif not has_proof and not has_co_occurrence:
                # The literal direct-remote-exec branch: a curl|sh string. In an actual
                # shell script (.sh/.bash) the string IS execution — leave it at full
                # confidence (the evil.example setup.sh case). In non-shell SOURCE the
                # string must be passed to an executor at runtime, which the atoms
                # alone can't prove — attenuate it below the bar.
                cited_langs = {langs_by_path.get(p) for p in paths if langs_by_path.get(p)}
                if cited_langs and not (cited_langs & _SHELL_LANGS):
                    _apply(f, _DIRECT_EXEC_IN_SOURCE)

    return findings


__all__ = ["apply_contextual_attenuators"]

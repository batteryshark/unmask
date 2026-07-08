---
name: mcd-report
capability: malicious-code-assessment
accepts: [tree]
emits: [report/html, report/markdown, report/json]
tier: read-only
run: scripts/run.sh
keywords: [parallax, mcd, malicious-code, malware, supply-chain, dropper, credential-theft, obfuscated-exec, backdoor, exfiltration, install-hook, disposition, quarantine, assessment, report, deterministic, static-analysis]
description: >-
  Deterministic malicious-code assessment: run the vendored parallax engine over a
  source tree, apply the MCD reading (observations -> BP-* bad-pattern compositions
  like install-time payload, download-and-execute dropper, credential theft +
  egress, obfuscated exec, backdoor, exfiltration), correlate + dispose, and render
  a self-contained HTML report plus Markdown and JSON. Severity (how bad if real)
  and confidence (how sure) stay separate; the output recommends a disposition
  (clear / review / quarantine), not a maliciousness verdict. All deterministic:
  no LLM, no network. Optionally folds an agentic-review overlay (per-finding
  reviewer verdicts) over the scan. The alternative to pure-LLM "is this malware?"
  guessing — goalpacks that want a reproducible, evidence-cited malicious-code
  report request this instead.
---

# mcd-report — source tree → malicious-code assessment report

The product half of the Parallax MCD pipeline. Where `code-understanding` emits the
judgment-free inventory of what code *can do*, this skill answers the malicious-code
question on top of it: it composes observation atoms into **BP-\* bad-pattern
compositions**, correlates co-located findings, recommends a **disposition**, and
renders an evidence-cited report.

## The pipeline

```
engine.observe(target)          -> (observations, inv)   # judgment-free atoms
mcd_lens.mcd_reading(obs, inv)  -> mcd findings          # BP-* compositions
engine.report.build(...)        -> scan-report dict
mcd_lens.build_assessment(...)  -> assessment dict       # correlate + dispose
render_html / render_markdown / to_json -> report.{html,md,json}
```

`engine` is the shared, product-neutral scanner (`parallax-goalpacks/engine/`);
`mcd_lens` (`parallax-goalpacks/mcd_lens/`) is the malicious-code reading + the
assessment/render layer. Both live at the repo root; `run.sh` puts the root on
`PYTHONPATH`.

The reading covers, among others: `BP-SUPPLY` (install-time payload), `BP-DROPPER`
(download-and-execute), `BP-CREDTHEFT` (credential access + egress), `BP-OBFEXEC`
(decode-and-execute), `BP-BACKDOOR`, `BP-EXFIL`, and the rest of `MCD_COMPOSITIONS`.

## Judgment model

- **Two independent axes.** Severity is how bad it would be if real; confidence is
  how sure the engine is that it is real. A finding can be high-severity and
  low-confidence at once — they are reported separately and never collapsed.
- **Disposition, not a verdict.** The report recommends a next action —
  `clear` / `review` / `quarantine` — by an explicit deterministic rule (quarantine
  needs a high/critical finding at proof-aware confidence >= 0.65, or a cross-signal
  correlated high/critical cluster). `clear` means "clear of mcd findings under the
  implemented compositions", not a safety guarantee.
- **Every finding states what would disprove it** and what to verify next.
- **Deterministic.** No LLM, no network. The old model-authored prose overlay
  (brief/polish) is intentionally not vendored; the executive summary is the
  engine's deterministic `_exec_summary`.

## Run

`tree-sitter` (a library parser — it never executes the target) is a read-only
dependency, which is why this skill is tier `read-only`.

```sh
scripts/run.sh <input_target> <out_dir> [adjudications_json]
```

Python resolution mirrors `code-understanding`: it reuses the code-understanding
skill's venv when present (so mcd-report needs no separate install), then this
skill's own `.venv` (`scripts/setup.sh`), then an ephemeral `uv run` with the pinned
deps, then system `python3` (regex fallback).

## Output

- `<out_dir>/report.html` — self-contained HTML (starts with `<!doctype html>`): the
  disposition banner, executive summary, each finding with evidence and disproof,
  correlations, reachability, and a "how to read this" guide.
- `<out_dir>/report.md` — the same assessment as Markdown.
- `<out_dir>/report.json` — the full `build_assessment` dict (summary, disposition,
  findings, correlations, enrichment, observations, coverage).

## Agentic-review overlay (optional)

Pass an `adjudications_json` file to fold a reviewer's per-finding verdicts over the
scan. The engine finds the shapes; the reviewer reads the code behind each and sets
a verdict (`confirm` / `escalate` / `deescalate` / `refute` / `suppress`), a reviewed
confidence, and a response tier. Shape:

```json
{
  "reviewer": {"backend": "pi", "model": "cheap", "role": "malicious-code reviewer"},
  "findings": [
    {"id": "mcd-001", "verdict": "escalate", "engineConfidence": 0.7,
     "reviewedConfidence": 0.9, "responseTier": 4, "excludedFromDisposition": false}
  ]
}
```

`build_adjudication` (in `scripts/report.py`) tallies the verdicts, records which
findings the review moved, derives a response level from the max response tier, and
recomputes a **reviewed disposition** over the non-excluded findings. The engine
still owns the authoritative deterministic disposition; the overlay adds a reviewed
one and the report renders both under an "Adjudication (agentic review)" section.

# reference/ — external reference material (not wired in)

Snapshots kept for reference only. **Nothing here is imported or maintained** by
unmask; the source of truth lives in the `parallax-goalpacks` repo. Diff against it
or borrow from it, but don't depend on it.

## `mcd-report/` — the deterministic MCD report renderer

Copied from `parallax-goalpacks/skills/mcd-report/` (`scripts/report.py` is the
renderer). It runs the parallax engine → MCD reading → `BP-*` compositions →
correlate/dispose → **self-contained HTML + Markdown + JSON**, keeping severity (how
bad if real) separate from confidence (how sure), and recommends a disposition
(clear / review / quarantine).

**Why it's here:** unmask already renders reports natively in
`packages/unmask/src/unmask/scanner/assess/render.py`, which was built to *parity*
this renderer's output — so this is effectively the **ancestor** of unmask's current
HTML. Kept as a reference to diff against and to mine for any HTML polish worth
pulling into the native renderer.

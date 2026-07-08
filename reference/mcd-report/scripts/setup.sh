#!/bin/sh
# Optional: set up an isolated uv venv for the mcd-report skill with the engine's
# pinned deps. Usually unnecessary — run.sh prefers the code-understanding skill's
# venv, which already carries these deps. Set this up only when mcd-report is used
# standalone (no code-understanding venv present). Idempotent.
# Usage: scripts/setup.sh
set -eu

SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
SKILL_DIR="$(cd "$SCRIPTS_DIR/.." && pwd)"
REPO_ROOT="$(cd "$SKILL_DIR/../.." && pwd)"

command -v uv >/dev/null 2>&1 || {
    echo "mcd-report/setup: 'uv' not found on PATH — install uv first" >&2
    echo "  (https://docs.astral.sh/uv/). It manages this skill's isolated venv." >&2
    exit 1
}

echo "mcd-report/setup: creating venv in $SKILL_DIR/.venv"
uv venv "$SKILL_DIR/.venv"

# Pinned to match the engine's deps (same set as code-understanding).
echo "mcd-report/setup: installing pinned engine deps"
VIRTUAL_ENV="$SKILL_DIR/.venv" uv pip install \
    "tree-sitter==0.25.2" \
    "tree-sitter-language-pack==1.12.0" \
    "jsonschema>=4.18"

# Smoke-check: engine + mcd_lens import and tree-sitter loaded (not regex fallback).
echo "mcd-report/setup: verifying"
PYTHONPATH="$REPO_ROOT" "$SKILL_DIR/.venv/bin/python" - <<'PY'
from engine import rules
from mcd_lens import mcd_reading, build_assessment, render_html  # noqa: F401
mode = rules.ast_mode()
print(f"  engine + mcd_lens import OK; observation mode = {mode}")
if mode != "tree-sitter":
    print("  WARNING: tree-sitter did not load; engine will use the regex fallback.")
PY

echo "mcd-report/setup: done. Run: scripts/run.sh <input_target> <out_dir> [adjudications_json]"

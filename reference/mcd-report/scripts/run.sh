#!/bin/sh
# Parallax MCD report: source tree -> malicious-code assessment (html/md/json).
# Usage: run.sh <input_target> <out_dir> [adjudications_json]
#
# Runs the deterministic engine scan + the mcd reading + the assessment layer and
# renders report.html / report.md / report.json into <out_dir>. All deterministic:
# no LLM, no network. If [adjudications_json] is given, an agentic-review overlay is
# folded over the scan (see report.py:build_adjudication).
#
# Python resolution mirrors code-understanding: the heavy deps (tree-sitter) live in
# the code-understanding skill's venv, so we reuse it when present; else this skill's
# own .venv; else an ephemeral `uv run` with the pinned deps; else system python3.
# The parallax-goalpacks repo root goes on PYTHONPATH so `import engine` and
# `import mcd_lens` resolve to the shared repo-root packages.
set -eu
[ $# -ge 2 ] && [ $# -le 3 ] || { echo "usage: run.sh <input_target> <out_dir> [adjudications_json]" >&2; exit 2; }
INPUT="$1"; OUT="$2"; ADJ="${3:-}"

SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
SKILL_DIR="$(cd "$SCRIPTS_DIR/.." && pwd)"
# repo root: parallax-goalpacks/  (skills/mcd-report -> ../..)
REPO_ROOT="$(cd "$SKILL_DIR/../.." && pwd)"

# The shared engine + mcd_lens live at the repo root; make imports find them.
export PYTHONPATH="$REPO_ROOT${PYTHONPATH:+:$PYTHONPATH}"

mkdir -p "$OUT"

# Prefer the code-understanding skill's venv (it already carries tree-sitter etc.),
# then this skill's own venv, so mcd-report needs no separate install.
CU_VENV_PY="$SKILL_DIR/../code-understanding/.venv/bin/python"
OWN_VENV_PY="$SKILL_DIR/.venv/bin/python"

if [ -x "$CU_VENV_PY" ]; then
    exec "$CU_VENV_PY" "$SCRIPTS_DIR/report.py" "$INPUT" "$OUT" ${ADJ:+"$ADJ"}
elif [ -x "$OWN_VENV_PY" ]; then
    exec "$OWN_VENV_PY" "$SCRIPTS_DIR/report.py" "$INPUT" "$OUT" ${ADJ:+"$ADJ"}
elif command -v uv >/dev/null 2>&1; then
    # No venv yet but uv is present — run in an ephemeral env with the pinned deps.
    exec uv run --with "tree-sitter==0.25.2" \
                --with "tree-sitter-language-pack==1.12.0" \
                --with "jsonschema>=4.18" \
                python "$SCRIPTS_DIR/report.py" "$INPUT" "$OUT" ${ADJ:+"$ADJ"}
else
    echo "mcd-report: no code-understanding venv, no skill venv (run scripts/setup.sh)," >&2
    echo "  and no 'uv' on PATH; falling back to system python3 — tree-sitter may be" >&2
    echo "  missing (engine will use its regex fallback)." >&2
    exec python3 "$SCRIPTS_DIR/report.py" "$INPUT" "$OUT" ${ADJ:+"$ADJ"}
fi

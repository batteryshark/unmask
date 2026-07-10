#!/usr/bin/env bash
#
# unmask setup — one command from a fresh clone to a working install.
#
#     ./setup.sh
#
# Installs the whole tool (core + RE add-on + review + MCP), optionally writes a .env
# for the agentic-review model, then checks the external RE tools (jadx / ilspycmd / …)
# and offers to install the simple ones. Safe to re-run. In a non-interactive shell it
# installs + reports and skips every prompt.

set -euo pipefail
cd "$(dirname "$0")"

bold() { printf '\n\033[1m%s\033[0m\n' "$1"; }
step() { printf '\n\033[1m▸ %s\033[0m\n' "$1"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$1"; }
info() { printf '    %s\n' "$1"; }

INTERACTIVE=0; [ -t 0 ] && INTERACTIVE=1
# ask PROMPT [DEFAULT] -> echoes the answer (the default when non-interactive/empty)
ask() {
  local prompt="$1" default="${2:-}" reply=""
  if [ "$INTERACTIVE" = 0 ]; then printf '%s' "$default"; return; fi
  read -r -p "$prompt" reply || reply=""
  printf '%s' "${reply:-$default}"
}
yesish() { case "$1" in y|Y|yes|YES) return 0;; *) return 1;; esac; }

# 1) uv ----------------------------------------------------------------------
step "Checking uv"
if ! command -v uv >/dev/null 2>&1; then
  warn "uv is not installed — it's the Python package manager unmask builds on."
  info "Install it, then re-run ./setup.sh:"
  info "  curl -LsSf https://astral.sh/uv/install.sh | sh     (or: brew install uv)"
  exit 1
fi
ok "uv $(uv --version 2>/dev/null | awk '{print $2}')"

# 2) install everything ------------------------------------------------------
step "Installing unmask (core + RE add-on + review + MCP)"
uv sync
ok "installed into .venv — run the tool with 'uv run unmask …'"

# 3) review model (optional) -------------------------------------------------
step "Agentic review model (optional)"
info "unmask's scan is fully deterministic and needs no model. The 'unmask run --review'"
info "overlay adjudicates findings with an LLM — configure it now, or skip and do it later"
info "by copying .env.example to .env."
if yesish "$(ask "  Configure a review model now? [y/N] " n)"; then
  provider=""; model=""; base=""; kind=""; key=""
  echo "    Providers:  1) openai   2) anthropic   3) lmstudio (local, OpenAI-wire)"
  echo "                4) custom (any OpenAI/Anthropic-compatible endpoint)   5) minimax   6) zai"
  case "$(ask "    choose [1-6]: " 1)" in
    1|openai)    provider=openai ;;
    2|anthropic) provider=anthropic ;;
    3|lmstudio)  provider=lmstudio; base="http://127.0.0.1:1234/v1" ;;
    4|custom)    provider=custom ;;
    5|minimax)   provider=minimax ;;
    6|zai)       provider=zai ;;
    *) warn "unrecognized choice — skipping model config"; provider="" ;;
  esac
  if [ -n "$provider" ]; then
    model=$(ask "    model id: " "")
    if [ "$provider" = lmstudio ] || [ "$provider" = custom ]; then
      base=$(ask "    base URL [${base:-required}]: " "$base")
    fi
    if [ "$provider" = custom ]; then
      kind=$(ask "    wire protocol [openai/anthropic]: " openai)
    fi
    key=$(ask "    API key (blank for a keyless local server): " "")

    [ -f .env ] && cp .env .env.bak && warn "backed up existing .env to .env.bak"
    # Preserve any non-review lines; replace only the UNMASK_REVIEW_* block.
    if [ -f .env ]; then grep -v '^UNMASK_REVIEW_' .env > .env.tmp 2>/dev/null || true; mv .env.tmp .env; fi
    {
      echo "UNMASK_REVIEW_PROVIDER=$provider"
      [ -n "$model" ] && echo "UNMASK_REVIEW_MODEL=$model"
      [ -n "$base" ]  && echo "UNMASK_REVIEW_BASE_URL=$base"
      [ -n "$kind" ]  && echo "UNMASK_REVIEW_KIND=$kind"
      [ -n "$key" ]   && echo "UNMASK_REVIEW_API_KEY=$key"
    } >> .env
    ok ".env written (gitignored). Run scans with: uv run unmask run --review ./target"
  fi
else
  info "skipped — 'cp .env.example .env' and edit when you want review."
fi

# 4) external RE tools -------------------------------------------------------
step "External RE tools"
doc="$(uv run unmask tools doctor --json 2>/dev/null || printf '{}')"
missing="$(printf '%s' "$doc" | uv run python -c 'import sys, json
try: d = json.load(sys.stdin)
except Exception: d = {}
for t in d.get("externalTools", []):
    if not t.get("present"): print(t["tool"])' 2>/dev/null || true)"

if [ -z "$missing" ]; then
  ok "all external tools present"
else
  os="$(uname)"
  info "These are OPTIONAL — each only gates one binary type; without it that type is an"
  info "honest blind spot, never a crash. Offering to install the simple ones:"
  for tool in $missing; do
    case "$tool" in
      jadx)  # Java/Android decompile
        if [ "$os" = Darwin ] && command -v brew >/dev/null 2>&1; then
          warn "jadx (Java/Android) missing — 'brew install jadx'"
          if yesish "$(ask "    install it now? [y/N] " n)"; then
            brew install jadx && ok "jadx installed" || warn "brew install jadx failed"
          fi
        else
          warn "jadx missing — install from https://github.com/skylot/jadx, put it on PATH (needs a JRE)"
        fi ;;
      ilspycmd)  # .NET decompile
        if command -v dotnet >/dev/null 2>&1; then
          warn "ilspycmd (.NET) missing — 'dotnet tool install -g ilspycmd'"
          if yesish "$(ask "    install it now? [y/N] " n)"; then
            dotnet tool install -g ilspycmd && ok "ilspycmd installed" || warn "dotnet tool install failed"
          fi
        else
          warn "ilspycmd missing — install the .NET SDK, then: dotnet tool install -g ilspycmd"
        fi ;;
      *)
        warn "$tool missing — see 'uv run unmask tools doctor' for the install hint" ;;
    esac
  done
fi

# 5) done --------------------------------------------------------------------
bold "Ready."
info "Scan something:      uv run unmask run ./suspicious-package"
info "Check readiness:     uv run unmask tools doctor"
info "Full options:        uv run unmask run --help"

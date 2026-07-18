#!/usr/bin/env bash
# bootstrap-newclone.sh — One-shot setup for a fresh clone of auditooor.
#
# Idempotent: safe to re-run. Venv-local only (does NOT modify ~/.bashrc or
# install anything globally). Pure bash; portable to macOS + Linux.
#
# Usage:  bash scripts/bootstrap-newclone.sh
#         (or: make bootstrap)
#
# See README.md for the public review path.

set -u
set -o pipefail

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  cat <<'EOF'
Usage: bash scripts/bootstrap-newclone.sh

One-shot setup for a fresh auditooor clone.

What it does:
  - checks bash, git, and python3 >= 3.10
  - creates a repo-local .venv/
  - installs requirements.txt into that venv when dependencies are missing
  - runs make judge-check

Notes:
  - this script is idempotent and does not install global packages
  - pip installation may require network access on a fresh machine
EOF
  exit 0
fi

if [ "${1:-}" != "" ]; then
  printf "Unknown argument: %s\nRun with --help for usage.\n" "$1" >&2
  exit 2
fi

# ─── Colors (no-op when stdout is not a tty) ─────────────────────────────────
if [ -t 1 ]; then
  RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'
  BOLD=$'\033[1m';   RESET=$'\033[0m'
else
  RED=""; GREEN=""; YELLOW=""; BOLD=""; RESET=""
fi
CHECK="${GREEN}✓${RESET}"
CROSS="${RED}✗${RESET}"

# Repo root = parent of scripts/
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

info()  { printf "  %s %s\n" "$1" "$2"; }
fatal() { printf "\n%s%s bootstrap failed:%s %s\n" "$RED" "$CROSS" "$RESET" "$1" >&2; exit 1; }

printf "%s== auditooor bootstrap ==%s  (%s)\n" "$BOLD" "$RESET" "$REPO_ROOT"

# ─── Step 1: required system deps ────────────────────────────────────────────
printf "\n%sStep 1/4:%s checking system dependencies\n" "$BOLD" "$RESET"

need_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    fatal "missing required command: $cmd (install it and re-run)"
  fi
  info "$CHECK" "$cmd: $(command -v "$cmd")"
}

need_cmd bash
need_cmd git
need_cmd python3

# python3 >= 3.10
PY_VERSION="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
PY_MAJOR="${PY_VERSION%.*}"; PY_MINOR="${PY_VERSION#*.}"
if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 10 ]; }; then
  fatal "python3 >= 3.10 required (found $PY_VERSION)"
fi
info "$CHECK" "python3 version: $PY_VERSION (>= 3.10)"

# ─── Step 2: venv + python deps ──────────────────────────────────────────────
printf "\n%sStep 2/4:%s python environment\n" "$BOLD" "$RESET"

VENV_DIR="$REPO_ROOT/.venv"
if [ ! -d "$VENV_DIR" ]; then
  info "·" "creating venv at .venv"
  python3 -m venv "$VENV_DIR" || fatal "failed to create venv at $VENV_DIR"
else
  info "$CHECK" "venv already exists at .venv"
fi
# shellcheck disable=SC1091
. "$VENV_DIR/bin/activate" || fatal "failed to activate venv"

REQ_FILE="$REPO_ROOT/requirements.txt"
MISSING_DEPS=()
for mod in tree_sitter tree_sitter_rust tree_sitter_move yaml; do
  if ! python3 -c "import $mod" >/dev/null 2>&1; then
    MISSING_DEPS+=("$mod")
  fi
done

if [ "${#MISSING_DEPS[@]}" -eq 0 ]; then
  info "$CHECK" "python deps present: tree_sitter, tree_sitter_rust, tree_sitter_move, pyyaml"
elif [ -f "$REQ_FILE" ]; then
  info "·" "missing: ${MISSING_DEPS[*]} — installing from requirements.txt"
  python3 -m pip install --quiet --upgrade pip || fatal "pip upgrade failed"
  python3 -m pip install --quiet -r "$REQ_FILE" || fatal "pip install -r requirements.txt failed"
  info "$CHECK" "installed from requirements.txt"
else
  printf "  %s%s%s no requirements.txt at repo root — skipping pip install\n" "$YELLOW" "!" "$RESET"
  printf "      missing modules: %s (install manually if needed)\n" "${MISSING_DEPS[*]}"
fi

# ─── Step 3: public sanity gate (read-only) ─────────────────────────────────
printf "\n%sStep 3/4:%s running 'make judge-check' as sanity gate\n" "$BOLD" "$RESET"
if make judge-check; then
  info "$CHECK" "make judge-check passed"
else
  fatal "'make judge-check' failed — fix the underlying issue and re-run"
fi

# ─── Step 4: success banner ──────────────────────────────────────────────────
printf "\n%sStep 4/4:%s done\n" "$BOLD" "$RESET"
cat <<EOF

${GREEN}${BOLD}┌──────────────────────────────────────────────────────────────┐${RESET}
${GREEN}${BOLD}│  ${CHECK} bootstrap complete — environment ready                  │${RESET}
${GREEN}${BOLD}└──────────────────────────────────────────────────────────────┘${RESET}

Next steps:
  1. Read ${BOLD}README.md${RESET}                   - judge review path
  2. Read ${BOLD}docs/HACKATHON_GUIDE.md${RESET}     - evidence boundary
  3. Activate the venv in new shells:  ${BOLD}source .venv/bin/activate${RESET}

EOF
exit 0

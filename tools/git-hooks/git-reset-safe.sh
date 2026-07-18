#!/usr/bin/env bash
# ============================================================================
# git-reset-safe.sh - Rule 55 wrapper around `git reset`.
#
# Invokes tools/git-hooks/pre-destructive-op-sibling-check.sh as a precondition
# check, then chains to real `git reset` if the check passes. Designed for git
# versions that lack a native pre-reset hook (mainline git as of 2.45 still
# has none).
#
# Usage:
#   tools/git-hooks/git-reset-safe.sh [--hard|--soft|--mixed|--merge|--keep] [<commit>]
#
# Recommended alias (in shell rc or per-session):
#   alias git-reset="bash $(git rev-parse --show-toplevel)/tools/git-hooks/git-reset-safe.sh"
#
# To enforce on every `git reset` (advanced - shell function override):
#   git() {
#     if [ "$1" = "reset" ]; then
#       shift
#       bash "$(command git rev-parse --show-toplevel)/tools/git-hooks/git-reset-safe.sh" "$@"
#       return $?
#     fi
#     command git "$@"
#   }
#
# Override (operator-driven housekeeping):
#   R55_REBUTTAL='reason' bash git-reset-safe.sh --hard HEAD
#
# Sibling rules:
#   * R36 (commit-pathspec-discipline) polices the COMMIT SHAPE.
#   * R55 (this rule) polices the DESTRUCTIVE OP PRECONDITION.
# ============================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE_SCRIPT="${SCRIPT_DIR}/pre-destructive-op-sibling-check.sh"

if [ ! -x "${GATE_SCRIPT}" ] && [ ! -f "${GATE_SCRIPT}" ]; then
  echo "[git-reset-safe] WARNING: gate script not found at ${GATE_SCRIPT}; running git reset directly" >&2
  exec git reset "$@"
fi

# Pass args to gate via env var (so it can detect --hard / --merge variants).
WRAPPER_OP="reset" \
WRAPPER_ARGS="$*" \
bash "${GATE_SCRIPT}"
GATE_RC=$?

if [ "${GATE_RC}" -ne 0 ]; then
  echo "[git-reset-safe] R55 gate refused the operation; aborting." >&2
  exit "${GATE_RC}"
fi

# Gate passed (or warned-only). Chain to real git reset.
exec git reset "$@"

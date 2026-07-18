#!/usr/bin/env bash
# ============================================================================
# git-stash-safe.sh - Rule 55 wrapper around `git stash drop` / `git stash clear`.
#
# Invokes tools/git-hooks/pre-destructive-op-sibling-check.sh as a precondition
# check, then chains to real `git stash` if the check passes. Companion to
# git-reset-safe.sh, git-checkout-safe.sh, git-clean-safe.sh.
#
# `git stash drop` and `git stash clear` permanently delete stashed entries.
# Sibling lanes that stashed in-flight work for later restoration lose that
# work if a separate integration / housekeeping lane runs `git stash drop`
# (or worse, `git stash clear`) targeting their entry.
#
# Behaviour:
#   - `git stash push` / `git stash save` / `git stash list` / `git stash show`
#     / `git stash apply` / `git stash pop` (which RESTORES) are NOT destructive
#     against sibling work; this wrapper passes them through directly.
#   - `git stash drop` and `git stash clear` ARE destructive; the gate is
#     consulted.
#   - In single-lane TTY use the gate is a no-op (no sibling pathspec
#     declarations); in shared-worktree parallel-dispatch it surfaces the risk.
#
# Usage:
#   tools/git-hooks/git-stash-safe.sh push -m my-rescue -- tools/foo.py
#   tools/git-hooks/git-stash-safe.sh drop stash@{2}
#   tools/git-hooks/git-stash-safe.sh clear
#
# Recommended alias (in shell rc or per-session):
#   alias git-stash="bash $(git rev-parse --show-toplevel)/tools/git-hooks/git-stash-safe.sh"
#
# Override (operator-driven housekeeping):
#   R55_REBUTTAL='reason' bash git-stash-safe.sh drop stash@{0}
#
# Sibling rules:
#   * R36 (commit-pathspec-discipline) polices the COMMIT SHAPE.
#   * R55 (this rule) polices the DESTRUCTIVE OP PRECONDITION.
# ============================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE_SCRIPT="${SCRIPT_DIR}/pre-destructive-op-sibling-check.sh"

if [ ! -x "${GATE_SCRIPT}" ] && [ ! -f "${GATE_SCRIPT}" ]; then
  echo "[git-stash-safe] WARNING: gate script not found at ${GATE_SCRIPT}; running git stash directly" >&2
  exec git stash "$@"
fi

# Only consult the gate on destructive sub-commands. `push`, `save`, `list`,
# `show`, `apply`, `pop` (restorative), `branch` (non-destructive) all pass
# through directly.
SUB="${1:-}"
case "${SUB}" in
  drop|clear)
    WRAPPER_OP="stash-drop" \
    WRAPPER_ARGS="$*" \
    bash "${GATE_SCRIPT}"
    GATE_RC=$?
    if [ "${GATE_RC}" -ne 0 ]; then
      echo "[git-stash-safe] R55 gate refused the operation; aborting." >&2
      exit "${GATE_RC}"
    fi
    ;;
  *)
    : # non-destructive sub-command; pass through
    ;;
esac

# Gate passed (or skipped). Chain to real git stash.
exec git stash "$@"

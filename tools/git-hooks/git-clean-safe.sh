#!/usr/bin/env bash
# ============================================================================
# git-clean-safe.sh - Rule 55 wrapper around `git clean`.
#
# Invokes tools/git-hooks/pre-destructive-op-sibling-check.sh as a precondition
# check, then chains to real `git clean` if the check passes. Companion to
# git-reset-safe.sh and git-checkout-safe.sh.
#
# `git clean -fd` is the third destructive-op pathway named in R55 doctrine
# (after `git reset --hard` and `git checkout -- <paths>`). It removes
# untracked files and directories - which can include sibling lanes'
# in-flight artifacts that have NOT yet been added to the index. The gate
# uses `git status -uno --porcelain` so it does NOT see untracked files
# directly, but the precondition check is preserved to catch the
# misclassification case (uncommitted tracked sibling-lane work present at
# the same time as a clean sweep targeting unrelated paths).
#
# Usage:
#   tools/git-hooks/git-clean-safe.sh -fd
#   tools/git-hooks/git-clean-safe.sh -fdx
#   tools/git-hooks/git-clean-safe.sh -nfd        # dry-run still wraps for parity
#
# Recommended alias (in shell rc or per-session):
#   alias git-clean="bash $(git rev-parse --show-toplevel)/tools/git-hooks/git-clean-safe.sh"
#
# Override (operator-driven housekeeping):
#   R55_REBUTTAL='reason' bash git-clean-safe.sh -fd
#
# Sibling rules:
#   * R36 (commit-pathspec-discipline) polices the COMMIT SHAPE.
#   * R55 (this rule) polices the DESTRUCTIVE OP PRECONDITION.
# ============================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE_SCRIPT="${SCRIPT_DIR}/pre-destructive-op-sibling-check.sh"

if [ ! -x "${GATE_SCRIPT}" ] && [ ! -f "${GATE_SCRIPT}" ]; then
  echo "[git-clean-safe] WARNING: gate script not found at ${GATE_SCRIPT}; running git clean directly" >&2
  exec git clean "$@"
fi

# Pass args to gate via env var (so it can detect -f / -d / -x variants).
WRAPPER_OP="clean" \
WRAPPER_ARGS="$*" \
bash "${GATE_SCRIPT}"
GATE_RC=$?

if [ "${GATE_RC}" -ne 0 ]; then
  echo "[git-clean-safe] R55 gate refused the operation; aborting." >&2
  exit "${GATE_RC}"
fi

# Gate passed (or warned-only). Chain to real git clean.
exec git clean "$@"

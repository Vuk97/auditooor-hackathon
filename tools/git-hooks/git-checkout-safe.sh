#!/usr/bin/env bash
# ============================================================================
# git-checkout-safe.sh - Rule 55 wrapper around `git checkout`.
#
# Invokes tools/git-hooks/pre-destructive-op-sibling-check.sh as a precondition
# check, then chains to real `git checkout` if the check passes. Companion to
# git-reset-safe.sh; covers the destructive `git checkout -- <paths>` and
# `git checkout <branch>` (with conflicting WT edits) pathways that R55
# version 1 ONLY protected against if invoked via wrapper.
#
# Empirical anchor (Phase NEG, 2026-05-23): lane NEG-F ran a bare
# `git checkout -- tools/vault-mcp-server.py` to revert its own edit and
# silently wiped sibling lane NEG-B's then-uncommitted edits to the same
# file. NEG-F itself surfaced the incident with "use the R55 wrapper
# instead of bare `git checkout --`" recommendation. This wrapper makes
# that recommendation actionable.
#
# Usage:
#   tools/git-hooks/git-checkout-safe.sh -- <paths...>
#   tools/git-hooks/git-checkout-safe.sh <branch>
#   tools/git-hooks/git-checkout-safe.sh -b <new-branch>
#
# Recommended alias (in shell rc or per-session):
#   alias git-checkout="bash $(git rev-parse --show-toplevel)/tools/git-hooks/git-checkout-safe.sh"
#
# To enforce on every `git checkout` (advanced - shell function override):
#   git() {
#     if [ "$1" = "checkout" ]; then
#       shift
#       bash "$(command git rev-parse --show-toplevel)/tools/git-hooks/git-checkout-safe.sh" "$@"
#       return $?
#     fi
#     command git "$@"
#   }
#
# Override (operator-driven housekeeping):
#   R55_REBUTTAL='reason' bash git-checkout-safe.sh -- tools/foo.py
#
# Sibling rules:
#   * R36 (commit-pathspec-discipline) polices the COMMIT SHAPE.
#   * R55 (this rule) polices the DESTRUCTIVE OP PRECONDITION.
# ============================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE_SCRIPT="${SCRIPT_DIR}/pre-destructive-op-sibling-check.sh"

if [ ! -x "${GATE_SCRIPT}" ] && [ ! -f "${GATE_SCRIPT}" ]; then
  echo "[git-checkout-safe] WARNING: gate script not found at ${GATE_SCRIPT}; running git checkout directly" >&2
  exec git checkout "$@"
fi

# Pass args to gate via env var (so it can detect '-- <paths>' file-revert
# variant vs branch-switch variant).
WRAPPER_OP="checkout" \
WRAPPER_ARGS="$*" \
bash "${GATE_SCRIPT}"
GATE_RC=$?

if [ "${GATE_RC}" -ne 0 ]; then
  echo "[git-checkout-safe] R55 gate refused the operation; aborting." >&2
  exit "${GATE_RC}"
fi

# Gate passed (or warned-only). Chain to real git checkout.
exec git checkout "$@"

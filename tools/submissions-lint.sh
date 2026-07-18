#!/usr/bin/env bash
# submissions-lint.sh — pre-commit gate for workspace SUBMISSIONS.md.
# Productized from R86 L1: manual polish rounds missed structural defects
# across agent-authored drafts. This wrapper runs the 21-check audit and
# exits 1 on any failure so the commit aborts.
#
# Usage:
#   ./tools/submissions-lint.sh <workspace>
#
# Or wire into git as a pre-commit hook (one-time setup):
#   ln -s $PWD/tools/submissions-lint.sh <workspace>/.git/hooks/pre-commit
#
# Exit codes:
#   0 — every draft in SUBMISSIONS.md Section 3 scores 21/21
#   1 — one or more drafts failed; commit should abort
#   2 — usage error / missing SCOPE.md or SUBMISSIONS.md

set -u
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ $# -lt 1 ]; then
    echo "usage: submissions-lint.sh <workspace>" >&2
    exit 2
fi

WS="$1"
[ -d "$WS" ] || { echo "[err] workspace not found: $WS" >&2; exit 2; }

python3 "$SCRIPT_DIR/submissions-lint.py" "$WS" --strict

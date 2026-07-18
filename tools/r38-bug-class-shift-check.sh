#!/usr/bin/env bash
# r38-bug-class-shift-check.sh - Wave-2 W2.9.a Check #73 wrapper.
#
# Thin shell wrapper around tools/bug-class-shift-check.py. Mirrors the
# pre-submit-check.sh gate calling convention used by Checks #58-#72:
#
#   - first positional arg is the draft path
#   - --severity {Critical|High|Medium|Low|auto}
#   - --json emits the canonical envelope
#   - exit 0 = pass / out-of-scope / ok-rebuttal
#     exit 1 = R38 violation (rubric vs attack_class mismatch OR
#              unacknowledged drift candidate)
#     exit 2 = error
#
# Source: docs/WAVE2_W29_NEW_GATES_SPEC_2026-05-16.md §1

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TOOL="$ROOT/tools/bug-class-shift-check.py"

if [ ! -f "$TOOL" ]; then
    echo "r38: tool not found ($TOOL)" >&2
    exit 2
fi

exec python3 "$TOOL" "$@"

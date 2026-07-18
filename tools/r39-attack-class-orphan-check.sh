#!/usr/bin/env bash
# r39-attack-class-orphan-check.sh - Wave-2 W2.9.b Check #74 wrapper.
#
# Thin shell wrapper around tools/attack-class-orphan-check.py. Mirrors the
# pre-submit-check.sh gate calling convention used by Checks #58-#72.
#
#   - first positional arg is the draft path
#   - --severity {Critical|High|Medium|Low|auto}
#   - --json emits the canonical envelope
#   - exit 0 = pass / out-of-scope / ok-rebuttal
#     exit 1 = R39 violation (orphan class without rebuttal)
#     exit 2 = error (distribution index unavailable)
#
# Source: docs/WAVE2_W29_NEW_GATES_SPEC_2026-05-16.md §2

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TOOL="$ROOT/tools/attack-class-orphan-check.py"

if [ ! -f "$TOOL" ]; then
    echo "r39: tool not found ($TOOL)" >&2
    exit 2
fi

exec python3 "$TOOL" "$@"

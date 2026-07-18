#!/usr/bin/env bash
# irdump.sh — generate a Slither IR dump readable via the Read tool
#
# Usage:
#   bash tools/irdump.sh <sol-file-or-project-dir> [contract_name] [function_name]
#
# Output:
#   Writes to <target>.irdump.txt  (or /tmp/irdump.txt if target is a directory)
#   Prints the output file path to stdout so agents know where to Read.

set -euo pipefail

export PATH="$HOME/.foundry/bin:$HOME/.local/bin:$PATH"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IRDUMP_PY="$SCRIPT_DIR/irdump.py"

if [[ $# -lt 1 ]]; then
    echo "Usage: bash irdump.sh <sol-file-or-project-dir> [contract_name] [function_name]" >&2
    exit 1
fi

TARGET="$1"
CONTRACT="${2:-}"
FUNCTION="${3:-}"

# Determine output file path
if [[ -d "$TARGET" ]]; then
    # For a directory target, use a slug based on the dir name
    SLUG="$(basename "$TARGET" | tr '/' '_' | tr ' ' '_')"
    OUTFILE="/tmp/irdump_${SLUG}.txt"
else
    OUTFILE="${TARGET}.irdump.txt"
fi

# Build argument list
ARGS=("$TARGET")
if [[ -n "$CONTRACT" ]]; then
    ARGS+=("$CONTRACT")
fi
if [[ -n "$FUNCTION" ]]; then
    ARGS+=("$FUNCTION")
fi

python3 "$IRDUMP_PY" "${ARGS[@]}" > "$OUTFILE"
echo "$OUTFILE"

#!/usr/bin/env bash
# latest-iter.sh — print the last N iteration rows from a workspace's SESSION_LOG.md
#
# Usage:
#   ./tools/latest-iter.sh <workspace-dir> [N]
#
# Default N = 5.
#
# Fixes Issue 1 from SKILL_ISSUES.md — tail returns trailing env, not iter rows.

set -uo pipefail

WS="${1:-}"
N="${2:-5}"

if [ -z "$WS" ]; then
    echo "Usage: $0 <workspace-dir> [N]"
    exit 1
fi

SL="$WS/SESSION_LOG.md"
if [ ! -f "$SL" ]; then
    echo "Error: $SL not found"
    exit 1
fi

# Iteration rows are table rows starting with "| <number> | <date>"
grep -E '^\| +[0-9]+ +\|' "$SL" | tail -"$N"

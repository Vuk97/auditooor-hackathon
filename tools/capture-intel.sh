#!/usr/bin/env bash
# capture-intel.sh — append user-provided external intel (articles, Discord, Tweets) to EXTERNAL_INTEL.md
#
# Usage:
#   ./tools/capture-intel.sh <workspace-dir> [title]
#
# Reads stdin and appends as a new entry to workspace/EXTERNAL_INTEL.md with
# a timestamp and optional title. Useful when the user hands over context
# mid-audit that should be preserved and reloaded on future orient cycles.
#
# Example:
#   pbpaste | ./tools/capture-intel.sh /path/to/workspace "Ghost fills on Polymarket"
#   echo "attacker is using incrementNonce trick" | ./tools/capture-intel.sh /path/to/workspace
#
# Fixes Issue 13 from SKILL_ISSUES.md — external intel should be captured once and
# surfaced automatically during orient, not re-pasted each session.

set -uo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <workspace-dir> [title]"
    echo "       Pipe intel content via stdin."
    exit 1
fi

WS="$1"
TITLE="${2:-Untitled intel}"

if [ ! -d "$WS" ]; then
    echo "Error: workspace $WS not found"
    exit 1
fi

OUT="$WS/EXTERNAL_INTEL.md"
TODAY=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Initialize file if missing
if [ ! -f "$OUT" ]; then
    cat > "$OUT" <<EOF
# External Intel — user-provided context

This file accumulates articles, Discord chatter, Tweets, and any other
external context the user hands over during the audit. Read during orient
on every iteration. This is usually the direct map of where bounty value
lives — team pain expressed in plain language.

---

EOF
fi

# Read stdin into a temp file to detect empty input
tmp=$(mktemp)
cat > "$tmp"
if [ ! -s "$tmp" ]; then
    echo "Error: no content piped via stdin"
    rm -f "$tmp"
    exit 1
fi

{
    echo "## $TITLE"
    echo ""
    echo "**Captured:** $TODAY"
    echo ""
    cat "$tmp"
    echo ""
    echo "---"
    echo ""
} >> "$OUT"

rm -f "$tmp"
echo "Appended '$TITLE' to $OUT"
wc -l "$OUT" | awk '{print "Total lines:", $1}'

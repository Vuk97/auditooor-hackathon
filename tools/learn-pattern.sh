#!/usr/bin/env bash
# learn-pattern.sh — append a bug-pattern stub to reference/bug_patterns_observed.md
#
# Usage:
#   ./tools/learn-pattern.sh <workspace-dir> <finding-id>
#
# Reads the `### <finding-id>` block from <workspace>/FINDINGS.md, extracts
# target / severity / mechanism lines, and appends a stub row to
# reference/bug_patterns_observed.md for hand-completion.
#
# Fields that get auto-populated:
#   - First observed (audit name + iter + finding-id)
#   - Severity achieved (from the Proposed severity or Status fields)
#   - Core mechanism (from the Mechanism section or Summary)
#
# Fields that need hand-filling after the stub is appended:
#   - Code smell
#   - Grep
#   - PoC archetype
#   - Scope-match gotchas
#   - Originality keywords cross-ref
#   - Anti-pattern cross-ref
#
# Fixes SKILL_ISSUES.md #23.

set -uo pipefail

if [ $# -lt 2 ]; then
    echo "Usage: $0 <workspace-dir> <finding-id>"
    echo "Example: $0 ~/audits/polymarket '#V1.C'"
    exit 1
fi

WS="$1"
FINDING_ID="$2"

FF="$WS/FINDINGS.md"
if [ ! -f "$FF" ]; then
    echo "Error: $FF not found"
    exit 1
fi

AUDITOOOR_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PAT_FILE="$AUDITOOOR_DIR/reference/bug_patterns_observed.md"
if [ ! -f "$PAT_FILE" ]; then
    echo "Error: $PAT_FILE not found — cannot append"
    exit 1
fi

# Extract the finding block: from `### <id>` to the next `### ` or end of file.
# Use awk since the block may span many lines and contain markdown tables.
block=$(awk -v id="$FINDING_ID" '
    $0 ~ "^### " && in_block { exit }
    $0 ~ "^### .*" id { in_block = 1 }
    in_block { print }
' "$FF")

if [ -z "$block" ]; then
    echo "Error: finding $FINDING_ID not found in $FF"
    echo "Expected a heading like: ### $FINDING_ID — <title>"
    exit 1
fi

# Extract the title line (first `### ` line of the block)
title=$(echo "$block" | head -1 | sed -E 's/^### *//')

# Extract severity (looks for `Proposed severity` or `Severity` or Status line)
severity=$(echo "$block" | grep -iE '\*\*Proposed severity\*\*|\*\*Severity\*\*' | head -1 | sed -E 's/.*\*\*(Proposed [Ss]everity|[Ss]everity)\*\* \| //; s/ \|.*//; s/\*\*//g' || true)
if [ -z "$severity" ]; then
    # Fallback: try to infer from status field
    if echo "$block" | grep -qiE 'SUBMITTED.*High|severity.*High'; then severity="High"
    elif echo "$block" | grep -qiE 'SUBMITTED.*Medium|severity.*Medium'; then severity="Medium"
    elif echo "$block" | grep -qiE 'SUBMITTED.*Low|severity.*Low'; then severity="Low"
    else severity="TBD"
    fi
fi

# Extract status (for "First observed" field context)
status=$(echo "$block" | grep -iE '\*\*Status\*\*' | head -1 | sed -E 's/.*\*\*Status\*\* \| //; s/ \|.*//; s/\*\*//g' || true)

# Extract file:line (if present in a Target or File:line field)
fileline=$(echo "$block" | grep -iE '\*\*File:line\*\*|\*\*Target\*\*' | head -1 | sed -E 's/.*\*\*[^*]*\*\* \| //; s/ \|.*//' | head -c 200)

# Extract the first sentence of the Summary / Mechanism section if present
summary=$(echo "$block" | awk '/^## Summary|^\*\*Mechanism|^## Mechanism/ {flag=1; next} flag && /^$/ {flag=0} flag' | head -5 | tr '\n' ' ' | head -c 500)
if [ -z "$summary" ]; then
    summary="(hand-fill the core mechanism)"
fi

# Get audit name from workspace basename
audit_name=$(basename "$WS")
today=$(date -u +%Y-%m-%d)

# Derive next pattern ID from existing ones
next_pid=$(grep -cE '^### P[0-9]+' "$PAT_FILE" 2>/dev/null || echo 0)
next_pid=$((next_pid + 1))

# Append stub
cat >> "$PAT_FILE" <<EOF

### P${next_pid} — (hand-fill a short class name) (stub from learn-pattern.sh $today)

| Field | Value |
|---|---|
| **First observed** | $audit_name, $FINDING_ID |
| **Severity achieved** | $severity |
| **Target** | $fileline |
| **Status at append time** | $status |
| **Core mechanism** | $summary |
| **Code smell** | TODO — what grep / question should surface this class on a new target? Must be actionable, not vibes. |
| **Grep** | TODO — concrete ripgrep / cast / awk command the operator runs in iter 1. |
| **PoC archetype** | TODO — \`fork\` (needs live state) or \`isolated\` (unit-testable). Which template to copy. |
| **Scope-match gotchas** | TODO — which bounty exclusion classes might kill this (centralization, privileged keys, by design, publicly disclosed). |
| **Originality keywords** | TODO — cross-reference the class in \`reference/originality_keywords.md\`. Add a new class there if none fits. |
| **Anti-pattern cross-ref** | TODO — which \`reference/anti_patterns.md\` entry applies when investigating this class. |
| **Other known instances** | TODO — or "none yet" if this is the first. |

> **Stub appended by \`tools/learn-pattern.sh\` on $today. Hand-fill the TODO
> fields before committing. Do NOT leave the stub with TODO rows in the file.**

EOF

echo "Appended pattern P${next_pid} stub for $FINDING_ID to $PAT_FILE"
echo "Fields auto-populated: First observed, Severity achieved, Target, Status, Core mechanism"
echo "Fields to hand-fill: Code smell, Grep, PoC archetype, Scope-match gotchas, Originality keywords, Anti-pattern cross-ref"
echo ""
echo "Edit now: $PAT_FILE"

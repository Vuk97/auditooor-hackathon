#!/usr/bin/env bash
# tools/lib/finding-patterns.sh — shared FINDINGS.md regex constants
#
# Sourced by coverage-report.sh and finding-stats.sh so both tools agree on
# what counts as submitted / ready / investigating / closed. Fixes SKILL_ISSUES
# #16 (the two tools previously used divergent regexes and reported disagreeing
# counts).
#
# Usage:
#   source "$(dirname "$0")/lib/finding-patterns.sh"
#   submitted=$(finding_count "$FINDINGS_FILE" SUBMITTED)
#
# All patterns are extended regex (use with `grep -iE`).

# Status category patterns — intentionally broad to catch the phrasing
# variations that accumulate across iterations when findings get re-labelled.
# Each pattern is applied with `grep -iE` (case-insensitive extended regex).
FINDING_PAT_SUBMITTED='🚀|SUBMITTED to|Submitted to|Status.*Submitted|Status.*SUBMITTED|SUBMITTED.*Cantina'
FINDING_PAT_READY='✅.*VERIFIED|✅.*Ready|ready to submit|pending submission|ready for submission|verified.*ready|PoC passing.*ready|PoC.*[0-9]+/[0-9]+|verified.*candidate.*submission|pending user decision|verified latent bug.*candidate'
FINDING_PAT_INVESTIGATING='draft|Draft|investigating|NEEDS POC|needs follow|awaiting verif|Documented, not submitted'
FINDING_PAT_CLOSED='❌ CLOSED|CLOSED —|CLOSED -|^- \[x\].*CLOSED|\bDUPE\b|\bdupe\b|not a finding|ineligible|~~.*CLOSED~~|Rejected\.|closed as informational|LIKELY DUPE.*CLOSED'

# Anchor pattern — every top-level finding entry starts with `### #<ID>` or
# `### **#<ID>`. Count these to get the total finding count.
# Note: POSIX char class `[A-Za-z0-9_]` is used instead of `\w` for BSD awk
# compatibility (macOS ships BSD awk which does not recognize `\w`).
FINDING_ANCHOR='^### \*{0,2}#[A-Za-z0-9_]'

# Count helper: count findings matching a status category in a FINDINGS.md file.
#   $1 = file path
#   $2 = status category name (SUBMITTED, READY, INVESTIGATING, CLOSED, ANCHOR)
#
# Counts ENTRIES (per ### anchor section) not raw line matches, so a finding body
# that mentions "CLOSED" multiple times in prose only counts once. The count is the
# number of ### sections in which the status pattern matches at least once.
finding_count() {
    local file="$1"
    local category="$2"

    if [ "$category" = "ANCHOR" ]; then
        local n
        n=$(grep -cE "$FINDING_ANCHOR" "$file" 2>/dev/null || true)
        echo "${n:-0}"
        return 0
    fi

    local pat_var="FINDING_PAT_${category}"
    local pat="${!pat_var:-}"
    if [ -z "$pat" ]; then
        echo "0"
        return 1
    fi

    awk -v anchor_pat="$FINDING_ANCHOR" -v status_pat="$pat" '
        BEGIN { IGNORECASE=1; count=0; matched_this=0 }
        $0 ~ anchor_pat {
            # Previous section closes here. Commit its match state.
            if (in_section && matched_this) { count++ }
            in_section = 1
            matched_this = 0
            next
        }
        in_section && $0 ~ status_pat {
            matched_this = 1
        }
        END {
            if (in_section && matched_this) { count++ }
            print count
        }
    ' "$file"
}

#!/usr/bin/env bash
# finding-stats.sh — count findings by status in a workspace's FINDINGS.md
#
# Usage:
#   ./tools/finding-stats.sh <workspace-dir>
#
# Fixes Issues 2, 16 from SKILL_ISSUES.md:
#   #2  — standardize status parsing across phrasing variations
#   #16 — share regex constants with coverage-report.sh via lib/finding-patterns.sh
#         so both tools report the same counts

set -uo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <workspace-dir>"
    exit 1
fi

WS="$1"
FF="$WS/FINDINGS.md"

if [ ! -f "$FF" ]; then
    echo "Error: $FF not found"
    exit 1
fi

# Load shared finding-patterns library
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/finding-patterns.sh
source "$SCRIPT_DIR/lib/finding-patterns.sh"

submitted=$(finding_count "$FF" SUBMITTED)
ready=$(finding_count "$FF" READY)
investigating=$(finding_count "$FF" INVESTIGATING)
closed=$(finding_count "$FF" CLOSED)
total=$(finding_count "$FF" ANCHOR)

echo "============================================"
echo "Findings stats: $FF"
echo "============================================"
echo "Total anchors:      $total"
echo "Submitted:          $submitted"
echo "Ready/verified:     $ready"
echo "Investigating:      $investigating"
echo "Closed/ineligible:  $closed"

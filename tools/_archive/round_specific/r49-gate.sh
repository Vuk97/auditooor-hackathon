#!/usr/bin/env bash
# r49-gate.sh — R49 Track D: one-shot pipeline runner + gate.
#
# Runs the full R49 canonical flow against a workspace and reports pass/fail:
#   1. flow-gate.sh <ws>
#   2. scan.sh <ws>
#   3. triage-to-draft.sh <ws>
#   4. stop-criteria-check.sh
#   5. are-we-smarter.sh
#
# Each step is timed; cumulative time printed at the end. Exit 0 iff every
# step exits 0 (or 2 for flow-gate soft-warn when --allow-soft-warn is set).
#
# Usage:
#   ./tools/r49-gate.sh <workspace> [--skip-scan] [--allow-soft-warn]
#
# Flags:
#   --skip-scan         Don't re-run scan.sh (useful when you already have
#                       a recent custom-detectors.log and want the triage
#                       side only). Scan is slow (~30s+).
#   --allow-soft-warn   Treat flow-gate soft-warns (exit 2) as success.
#
# Exit codes:
#   0 — every step passed
#   1 — at least one step failed
#   2 — usage error

set -u

AUDITOOOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS_DIR="$AUDITOOOR_DIR/tools"

WS="${1:-}"
if [ -z "$WS" ] || [ ! -d "$WS" ]; then
    echo "usage: $0 <workspace> [--skip-scan] [--allow-soft-warn]" >&2
    exit 2
fi
shift

SKIP_SCAN=0
ALLOW_SOFT=0
while [ $# -gt 0 ]; do
    case "$1" in
        --skip-scan) SKIP_SCAN=1 ;;
        --allow-soft-warn) ALLOW_SOFT=1 ;;
        -h|--help)
            sed -n '1,25p' "$0" | sed 's/^#//'
            exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
    shift
done

# Timing scaffolding.
declare -a STEP_NAMES
declare -a STEP_RESULTS
declare -a STEP_TIMES

run_step() {
    local name="$1"; shift
    local allow_soft="${1:-0}"; shift 2>/dev/null || true
    local cmd="$*"
    local t0 t1 rc
    printf '\n── %s ──\n' "$name"
    t0=$(date +%s)
    eval "$cmd"
    rc=$?
    t1=$(date +%s)
    local elapsed=$((t1 - t0))
    local result="FAIL"
    if [ "$rc" = 0 ]; then
        result="PASS"
    elif [ "$rc" = 2 ] && [ "$allow_soft" = 1 ]; then
        result="SOFT-WARN (pass)"
    fi
    STEP_NAMES+=("$name")
    STEP_RESULTS+=("$result")
    STEP_TIMES+=("${elapsed}s")
    printf '   → %s in %ss (rc=%d)\n' "$result" "$elapsed" "$rc"
    if [[ "$result" == "FAIL" ]]; then
        return 1
    fi
    return 0
}

T0_TOTAL=$(date +%s)
OVERALL=0

# Step 1: flow-gate
FLOW_ALLOW=0
[ "$ALLOW_SOFT" = 1 ] && FLOW_ALLOW=1
run_step "flow-gate" "$FLOW_ALLOW" "$TOOLS_DIR/flow-gate.sh '$WS'" || OVERALL=1

# Step 2: scan (skippable).
if [ "$SKIP_SCAN" = 1 ]; then
    printf '\n── scan (SKIPPED) ──\n'
    STEP_NAMES+=("scan")
    STEP_RESULTS+=("SKIPPED")
    STEP_TIMES+=("0s")
else
    run_step "scan" 0 "$TOOLS_DIR/scan.sh '$WS'" || OVERALL=1
fi

# Step 3: triage-to-draft.
run_step "triage-to-draft" 0 "$TOOLS_DIR/triage-to-draft.sh '$WS'" || OVERALL=1

# Step 4: stop-criteria-check (workspace-agnostic).
run_step "stop-criteria-check" 0 "$TOOLS_DIR/stop-criteria-check.sh" || OVERALL=1

# Step 5: are-we-smarter (workspace-agnostic; print only first 40 lines).
run_step "are-we-smarter" 0 "$TOOLS_DIR/are-we-smarter.sh | head -40" || OVERALL=1

T1_TOTAL=$(date +%s)
TOTAL_ELAPSED=$((T1_TOTAL - T0_TOTAL))

# Summary table.
printf '\n=== r49-gate summary ===\n\n'
printf '%-25s %-20s %s\n' "STEP" "RESULT" "TIME"
printf '%-25s %-20s %s\n' "----" "------" "----"
for i in "${!STEP_NAMES[@]}"; do
    printf '%-25s %-20s %s\n' "${STEP_NAMES[$i]}" "${STEP_RESULTS[$i]}" "${STEP_TIMES[$i]}"
done
printf '%-25s %-20s %s\n' "----" "------" "----"
printf '%-25s %-20s %ss\n' "TOTAL" "$([ $OVERALL = 0 ] && echo PASS || echo FAIL)" "$TOTAL_ELAPSED"

exit "$OVERALL"

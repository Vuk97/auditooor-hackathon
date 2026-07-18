#!/usr/bin/env bash
# continuous-verification.sh — periodic health check loop.
#
# Usage:
#   bash tools/continuous-verification.sh            # default: every 5 min, 60 min total
#   bash tools/continuous-verification.sh 10 120     # every 10 min, 120 min total
#   bash tools/continuous-verification.sh --once     # single run then exit
#
# Output:
#   logs/continuous-verification/YYYYMMDD-HHMMSS.log
#
# Each log entry includes: make all result, dashboard output,
# parity %, test pass count.
#
# Exit codes:
#   0 — all runs healthy (or loop completed)
#   1 — VERDICT is BROKEN on at least one run; log path printed
#   2 — usage error
#
# PR #84 Phase 11 — complements CI (one-shot per push) with continuous
# background health snapshots while mining / batch-editing.

set -u
set -o pipefail

# ── Resolve repo root (script lives in tools/) ────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

LOG_DIR="$REPO_ROOT/logs/continuous-verification"
mkdir -p "$LOG_DIR"

# ── Parse args ────────────────────────────────────────────────────────────
ONCE=0
PERIOD_MIN=5
TOTAL_MIN=60

if [[ $# -eq 0 ]]; then
    :  # defaults
elif [[ "${1:-}" == "--once" ]]; then
    ONCE=1
elif [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    sed -n '2,18p' "$0"; exit 0
elif [[ $# -eq 2 ]]; then
    PERIOD_MIN="$1"
    TOTAL_MIN="$2"
    if ! [[ "$PERIOD_MIN" =~ ^[0-9]+$ ]] || ! [[ "$TOTAL_MIN" =~ ^[0-9]+$ ]]; then
        echo "error: period_min and total_min must be positive integers" >&2
        exit 2
    fi
else
    echo "error: expected 0 args, --once, or 'period_min total_min'" >&2
    echo "run with --help for usage" >&2
    exit 2
fi

# ── Health check runner ───────────────────────────────────────────────────
RUNS=0
HEALTHY=0
BROKEN=0
LAST_BROKEN_LOG=""

run_once() {
    RUNS=$((RUNS + 1))
    local ts log
    ts="$(date +%Y%m%d-%H%M%S)"
    log="$LOG_DIR/$ts.log"

    {
        echo "=== continuous-verification run $RUNS ==="
        echo "timestamp: $(date -Iseconds 2>/dev/null || date)"
        echo "repo: $REPO_ROOT"
        echo "host: $(hostname)"
        echo ""
        echo "--- make all ---"
    } > "$log"

    local all_rc=0
    make all >> "$log" 2>&1 || all_rc=$?

    {
        echo ""
        echo "--- make dashboard ---"
    } >> "$log"

    local dash_rc=0
    make dashboard >> "$log" 2>&1 || dash_rc=$?

    # Extract key signals from the log for console summary.
    local parity_line tests_line verdict
    parity_line="$(grep -E 'bidirectional=[0-9]+' "$log" | tail -1 || true)"
    tests_line="$(grep -E '[0-9]+/[0-9]+' "$log" | grep -iE 'pass|fixture' | tail -1 || true)"
    verdict="$(grep -iE '^VERDICT|verdict:' "$log" | tail -1 || true)"

    local status="HEALTHY"
    if [[ $all_rc -ne 0 ]] || echo "$verdict" | grep -qi BROKEN; then
        status="BROKEN"
        BROKEN=$((BROKEN + 1))
        LAST_BROKEN_LOG="$log"
    else
        HEALTHY=$((HEALTHY + 1))
    fi

    {
        echo ""
        echo "--- summary ---"
        echo "make_all_rc: $all_rc"
        echo "dashboard_rc: $dash_rc"
        echo "parity: ${parity_line:-n/a}"
        echo "tests: ${tests_line:-n/a}"
        echo "verdict: ${verdict:-n/a}"
        echo "status: $status"
    } >> "$log"

    printf '[%s] run %d  %s  rc=%d  %s\n' \
        "$(date +%H:%M:%S)" "$RUNS" "$status" "$all_rc" "$log"
    if [[ -n "$parity_line" ]]; then echo "    $parity_line"; fi
    if [[ -n "$verdict"     ]]; then echo "    $verdict";     fi

    if [[ "$status" == "BROKEN" ]]; then
        echo "[!] BROKEN — see $log" >&2
        return 1
    fi
    return 0
}

# ── Main loop ─────────────────────────────────────────────────────────────
if [[ $ONCE -eq 1 ]]; then
    run_once || { echo "BROKEN log: $LAST_BROKEN_LOG" >&2; exit 1; }
    echo ""
    echo "[summary] 1 run — $HEALTHY healthy, $BROKEN broken"
    exit 0
fi

START_EPOCH="$(date +%s)"
DEADLINE=$((START_EPOCH + TOTAL_MIN * 60))
PERIOD_SEC=$((PERIOD_MIN * 60))

echo "[continuous-verification] period=${PERIOD_MIN}m total=${TOTAL_MIN}m logs=$LOG_DIR"

while :; do
    run_once || true  # keep looping even if broken; summary counts it
    now="$(date +%s)"
    if (( now + PERIOD_SEC > DEADLINE )); then
        break
    fi
    echo "[sleep] ${PERIOD_MIN}m until next run (elapsed $(( (now - START_EPOCH) / 60 ))m / ${TOTAL_MIN}m)"
    sleep "$PERIOD_SEC"
done

echo ""
echo "[summary] $RUNS runs — $HEALTHY healthy, $BROKEN broken"
if [[ $BROKEN -gt 0 ]]; then
    echo "last broken log: $LAST_BROKEN_LOG" >&2
    exit 1
fi
exit 0

#!/usr/bin/env bash
# scan-full.sh — R88: master orchestrator that runs EVERY scanner in order.
#
# Root cause R88 fixes: R81-R87 cumulative scan-coverage audits flagged the
# same tools as NEVER-RAN in every round (concolic, economic-hypotheses-ir,
# slither-patch) but each round only ran the scanners the operator remembered.
# This script makes "run everything" one command so it stops being skippable.
#
# Order is NOT arbitrary — each layer is most useful with the prior layers'
# output already in place:
#   1. env-check.sh            — installs halmos + mythril + solc versions
#   2. fix-remappings.sh        — strip `=./` remap poison (R80 T5)
#   3. mixed-pragma-build.sh    — per-subtree build so downstream scanners compile
#   4. scan.sh                  — pattern hits (fast)
#   5. run-slither.sh           — slither + aderyn + semgrep
#   6. scan-all-modules-multisolc.sh — run_custom.py per subtree
#   7. R76 analyzers (attack-path, acl-matrix, storage-layout, integration-assumptions, missing-check-catalog, invariant-proposer)
#   8. concolic-scan.sh         — halmos symbolic (PREVIOUSLY SKIPPED)
#   9. economic-hypotheses-ir.sh — economic invariants (PREVIOUSLY SKIPPED)
#
# Each step writes its output to <ws> and logs to <ws>/scan-full.log. On step
# failure the script CONTINUES (records the failure in scan-full-summary.md)
# so a partial scan is still useful — unless --strict is passed.
#
# Usage:
#   bash tools/scan-full.sh <workspace>
#   bash tools/scan-full.sh <workspace> --strict    # abort on any step failure
#   bash tools/scan-full.sh <workspace> --skip STEP  # skip named step (e.g. --skip concolic)
#
# Exit codes:
#   0 — all mandatory steps succeeded (or --strict not set and all soft-fails)
#   1 — usage error
#   2 — --strict + any step failed

set -u
WS="${1:-}"
if [ -z "$WS" ] || [ ! -d "$WS" ]; then
    echo "usage: $0 <workspace> [--strict] [--skip STEP]" >&2
    exit 1
fi
shift || true

STRICT=0
SKIP_STEPS=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --strict) STRICT=1; shift ;;
        --skip)   SKIP_STEPS="$SKIP_STEPS $2"; shift 2 ;;
        *) echo "[err] unknown arg: $1" >&2; exit 1 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUDITOOOR_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG="$WS/scan-full.log"
SUMMARY="$WS/scan-full-summary.md"

: > "$LOG"
: > "$SUMMARY"
echo "# scan-full.sh run summary" > "$SUMMARY"
echo "" >> "$SUMMARY"
echo "Workspace: \`$WS\`" >> "$SUMMARY"
echo "Started: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$SUMMARY"
echo "" >> "$SUMMARY"
echo "| Step | Status | Output |" >> "$SUMMARY"
echo "|---|---|---|" >> "$SUMMARY"

fail_count=0
pass_count=0

_run_step() {
    local name="$1"
    local cmd="$2"
    local output_path="$3"

    # Honor --skip
    for skip in $SKIP_STEPS; do
        if [ "$skip" = "$name" ]; then
            echo "| $name | SKIPPED (--skip) | — |" >> "$SUMMARY"
            echo "[scan-full] $name: SKIPPED (--skip)" | tee -a "$LOG"
            return 0
        fi
    done

    echo "" | tee -a "$LOG"
    echo "========================================" | tee -a "$LOG"
    echo "[scan-full] step: $name" | tee -a "$LOG"
    echo "[scan-full] cmd:  $cmd" | tee -a "$LOG"
    echo "========================================" | tee -a "$LOG"

    local rc=0
    eval "$cmd" >>"$LOG" 2>&1 || rc=$?
    if [ $rc -eq 0 ]; then
        pass_count=$((pass_count + 1))
        echo "| $name | OK | \`$output_path\` |" >> "$SUMMARY"
        echo "[scan-full] $name: OK" | tee -a "$LOG"
    else
        fail_count=$((fail_count + 1))
        echo "| $name | FAIL (rc=$rc) | check $LOG |" >> "$SUMMARY"
        echo "[scan-full] $name: FAIL rc=$rc" | tee -a "$LOG"
        if [ "$STRICT" -eq 1 ]; then
            echo "[scan-full] STRICT mode — aborting" >&2
            exit 2
        fi
    fi
}

# ── Step 1: env-check (installs halmos + mythril + solc versions) ──
_run_step "env-check" \
    "bash '$AUDITOOOR_DIR/tools/env-check.sh' '$WS'" \
    "(stdout only)"

# ── Step 2: fix-remappings ──
if [ -x "$AUDITOOOR_DIR/tools/fix-remappings.sh" ]; then
    _run_step "fix-remappings" \
        "bash '$AUDITOOOR_DIR/tools/fix-remappings.sh' '$WS'" \
        "$WS/remappings.txt"
fi

# ── Step 3: mixed-pragma-build ──
if [ -x "$AUDITOOOR_DIR/tools/mixed-pragma-build.sh" ]; then
    _run_step "mixed-pragma-build" \
        "bash '$AUDITOOOR_DIR/tools/mixed-pragma-build.sh' '$WS'" \
        "$WS/out-mixed/"
fi

# ── Step 4: pattern scan ──
if [ -x "$AUDITOOOR_DIR/tools/scan.sh" ]; then
    _run_step "pattern-scan" \
        "bash '$AUDITOOOR_DIR/tools/scan.sh' '$WS'" \
        "$WS/PATTERN_HITS.md"
fi

# ── Step 5: slither + aderyn + semgrep ──
if [ -x "$AUDITOOOR_DIR/tools/run-slither.sh" ]; then
    _run_step "run-slither" \
        "bash '$AUDITOOOR_DIR/tools/run-slither.sh' '$WS'" \
        "$WS/slither.json"
fi

# ── Step 6: custom detectors per subtree ──
if [ -x "$AUDITOOOR_DIR/tools/scan-all-modules-multisolc.sh" ]; then
    _run_step "custom-detectors-multisolc" \
        "bash '$AUDITOOOR_DIR/tools/scan-all-modules-multisolc.sh' '$WS' --force" \
        "$WS/custom-detectors.log"
fi

# ── Step 7: R76 analyzers ──
for analyzer in attack-path acl-matrix storage-layout integration-assumptions missing-check-catalog invariant-proposer; do
    tool="$AUDITOOOR_DIR/tools/$analyzer.py"
    if [ -f "$tool" ]; then
        _run_step "r76-$analyzer" \
            "python3 '$tool' '$WS'" \
            "$WS/$(echo "$analyzer" | tr - _).md"
    fi
done

# ── Step 8: concolic-scan (PREVIOUSLY SKIPPED across R77-R87) ──
if [ -x "$AUDITOOOR_DIR/tools/concolic-scan.sh" ]; then
    _run_step "concolic-scan (halmos symbolic)" \
        "bash '$AUDITOOOR_DIR/tools/concolic-scan.sh' '$WS' --tool halmos --timeout 600" \
        "$WS/concolic/SUMMARY.md"
fi

# ── Step 9: economic-hypotheses-ir (PREVIOUSLY SKIPPED across R77-R87) ──
if [ -x "$AUDITOOOR_DIR/tools/economic-hypotheses-ir.sh" ]; then
    _run_step "economic-hypotheses-ir" \
        "bash '$AUDITOOOR_DIR/tools/economic-hypotheses-ir.sh' '$WS'" \
        "$WS/economic_hypotheses.md"
fi

echo "" >> "$SUMMARY"
echo "Completed: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$SUMMARY"
echo "" >> "$SUMMARY"
echo "**Totals: $pass_count OK, $fail_count FAIL**" >> "$SUMMARY"

echo ""
echo "[scan-full] done. $pass_count OK, $fail_count FAIL"
echo "[scan-full] summary: $SUMMARY"
echo "[scan-full] log:     $LOG"

if [ "$STRICT" -eq 1 ] && [ "$fail_count" -gt 0 ]; then
    exit 2
fi
exit 0

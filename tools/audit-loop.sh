#!/usr/bin/env bash
# audit-loop.sh — Deprecated legacy orchestration wrapper kept for reference.
#
# Phases:
#   1. ORIENT   — CCIA + mining-prioritizer + environment checks
#   2. DEEP-SCAN — mining-brief-generator for top targets
#   3. LEVERAGE  — cross-ws-pattern-mapper + variant detection
#   4. SWARM     — swarm discover (briefs)
#   5. MANUAL    — agent dispatch (human does this)
#   6. SYNTHESIZE — agent-output-synthesizer + swarm synthesis
#   7. GATEKEEP  — finding-quality-scorer + auto-fix + pre-submit-check
#   8. SUMMARY   — report + engagement-retro suggestion
#
# Usage:
#   ./tools/audit-loop.sh <workspace-dir> [--phase <1-8>] [--resume]
#   ./tools/audit-loop.sh ~/audits/polymarket          # run all
#   ./tools/audit-loop.sh ~/audits/polymarket --phase 2 # run only phase 2
#   ./tools/audit-loop.sh ~/audits/polymarket --resume  # resume from stored phase

# ---------------------------------------------------------------------------
# DEPRECATION NOTICE (2026-04-21)
# ---------------------------------------------------------------------------
# audit-loop.sh is DEPRECATED. All functionality has been merged into
# engage.py as first-class stages. Use engage.py instead:
#
#   python3 tools/engage.py --workspace <ws> --stage all
#   python3 tools/engage.py --workspace <ws> --stage mine-prioritize
#   python3 tools/engage.py --workspace <ws> --stages orient,scan,report
#
# This script is kept for reference but will not receive updates.
# ---------------------------------------------------------------------------

set -uo pipefail

# Print deprecation warning to stderr (once, not on --resume loops)
if [ "${AUDIT_LOOP_SILENT:-}" != "1" ]; then
    echo "[audit-loop] WARNING: audit-loop.sh is DEPRECATED." >&2
    echo "[audit-loop] Use engage.py instead: python3 tools/engage.py --workspace <ws> --stage all" >&2
fi

WS="${1:-}"
PHASE="all"
RESUME=0
shift 2>/dev/null || true

while [ $# -gt 0 ]; do
    case "$1" in
        --phase) PHASE="$2"; shift 2 ;;
        --resume) RESUME=1; shift ;;
        *) shift ;;
    esac
done

if [ -z "$WS" ] || [ ! -d "$WS" ]; then
    echo "usage: $0 <workspace-dir> [--phase <1-8>] [--resume]" >&2
    exit 1
fi

AUDITOOOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WS_NAME=$(basename "$WS")
LOG="$WS/audit-loop.log"

# Resolve forge for any compilation steps
source "$AUDITOOOR_DIR/tools/lib/forge-resolve.sh" 2>/dev/null || true

log() {
    echo "[audit-loop] $1" | tee -a "$LOG"
}

_state() {
    python3 "$AUDITOOOR_DIR/tools/workspace-state.py" "$@" 2>/dev/null
}

# Ensure workspace is tracked
_state get "$WS" >/dev/null 2>&1 || _state init "$WS" --name "$WS_NAME" >/dev/null 2>&1

# If --resume, read stored phase
if [ "$RESUME" -eq 1 ]; then
    STORED_PHASE=$(_state get "$WS" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('phase',1))" 2>/dev/null || echo "1")
    if [ "$PHASE" = "all" ]; then
        PHASE="$STORED_PHASE"
        log "Resuming from stored phase: $PHASE"
    else
        log "--resume ignored because --phase was explicitly set"
    fi
fi

_advance() {
    local next="$1"
    _state set "$WS" --phase "$next" >/dev/null 2>&1 || true
}

# ---------------------------------------------------------------------------
# Phase 1: ORIENT — CCIA + Prioritizer + Environment
# ---------------------------------------------------------------------------
run_phase_1() {
    log "=== Phase 1: ORIENT ==="

    # 1a. Generate CCIA if missing or stale (>24h)
    local ccia="$WS/ccia_report.md"
    if [ ! -f "$ccia" ] || [ -n "$(find "$WS" -name 'ccia_report.md' -mtime +1 2>/dev/null)" ]; then
        log "Generating CCIA report ..."
        python3 "$AUDITOOOR_DIR/tools/ccia.py" "$WS" --report "$ccia" 2>&1 | tee -a "$LOG"
    else
        log "CCIA report exists and is fresh: $ccia"
    fi

    # 1b. Environment health check
    log "Environment health check ..."
    if command -v forge >/dev/null 2>&1; then
        log "  forge: $(forge --version 2>&1 | head -1)"
    else
        log "  ⚠️  forge not found"
    fi
    python3 "$AUDITOOOR_DIR/tools/solc-version-manager.py" "$WS" 2>&1 | tee -a "$LOG"

    # 1c. Mining prioritizer — ranked targets
    log "Running mining-prioritizer ..."
    python3 "$AUDITOOOR_DIR/tools/mining-prioritizer.py" "$WS" --top 15 2>&1 | tee -a "$LOG"

    # 1d. Forge dependency check
    if [ -f "$WS/foundry.toml" ] || [ -d "$WS/lib" ]; then
        log "Running forge-deps-checker ..."
        python3 "$AUDITOOOR_DIR/tools/forge-deps-checker.py" "$WS" 2>&1 | tee -a "$LOG"
    fi

    log "Phase 1 complete."
    _advance 2
}

# ---------------------------------------------------------------------------
# Phase 2: DEEP-SCAN — Mining briefs for top targets
# ---------------------------------------------------------------------------
run_phase_2() {
    log "=== Phase 2: DEEP-SCAN ==="

    # Generate mining briefs for top 10 targets
    log "Generating mining briefs (top 10) ..."
    python3 "$AUDITOOOR_DIR/tools/mining-brief-generator.py" "$WS" --top 10 --output "$WS/mining_briefs/" 2>&1 | tee -a "$LOG"

    # Quick variant detection on all generated briefs
    if [ -d "$WS/mining_briefs" ]; then
        log "Running variant detection on briefs ..."
        for brief in "$WS"/mining_briefs/*.md; do
            [ -f "$brief" ] || continue
            python3 "$AUDITOOOR_DIR/tools/variant-detector.py" "$WS" "$brief" 2>&1 | tee -a "$LOG"
        done
    fi

    log "Phase 2 complete."
    _advance 3
}

# ---------------------------------------------------------------------------
# Phase 3: LEVERAGE — Cross-workspace patterns + variant detection
# ---------------------------------------------------------------------------
run_phase_3() {
    log "=== Phase 3: LEVERAGE ==="

    # Cross-workspace pattern mapping
    log "Running cross-ws-pattern-mapper ..."
    python3 "$AUDITOOOR_DIR/tools/cross-ws-pattern-mapper.py" "$WS" 2>&1 | tee -a "$LOG"

    # If we have past submissions in this workspace, run variant detection
    if [ -f "$WS/SUBMISSIONS.md" ] || [ -d "$WS/submissions" ]; then
        log "Checking for variants of past submissions ..."
        for f in "$WS"/submissions/staging/*.md; do
            [ -f "$f" ] || continue
            python3 "$AUDITOOOR_DIR/tools/variant-detector.py" "$WS" "$f" 2>&1 | tee -a "$LOG"
        done
    fi

    log "Phase 3 complete."
    _advance 4
}

# ---------------------------------------------------------------------------
# Phase 4: SWARM DISCOVER
# ---------------------------------------------------------------------------
run_phase_4() {
    log "=== Phase 4: SWARM DISCOVER ==="
    log "Running swarm-orchestrator.py --discover ..."
    python3 "$AUDITOOOR_DIR/tools/swarm-orchestrator.py" "$WS" --discover --src src 2>&1 | tee -a "$LOG"
    local rc=${PIPESTATUS[0]}
    if [ $rc -ne 0 ]; then
        log "WARN: swarm discover exited $rc"
    fi
    log "Phase 4 complete. Briefs: $WS/swarm/brief_*.md"
    _advance 5
}

# ---------------------------------------------------------------------------
# Phase 5: MANUAL — Agent Dispatch
# ---------------------------------------------------------------------------
run_phase_5() {
    log "=== Phase 5: MANUAL — Agent Dispatch ==="
    log "Printing dispatch commands ..."
    python3 "$AUDITOOOR_DIR/tools/swarm-orchestrator.py" "$WS" --dispatch --max-agents 11 2>&1 | tee -a "$LOG"
    log ""
    log "******************************************"
    log "MANUAL STEP REQUIRED:"
    log "  1. Copy the dispatch commands above"
    log "  2. Paste them into your Claude Code conversation"
    log "  3. Wait for all agents to complete"
    log "  4. Then re-run: $0 $WS --resume"
    log "******************************************"
    # Don't auto-advance — wait for manual completion
}

# ---------------------------------------------------------------------------
# Phase 6: SYNTHESIZE — Agent outputs + swarm synthesis
# ---------------------------------------------------------------------------
run_phase_6() {
    log "=== Phase 6: SYNTHESIZE ==="

    # New: agent-output-synthesizer for structured verdict extraction
    log "Running agent-output-synthesizer ..."
    python3 "$AUDITOOOR_DIR/tools/agent-output-synthesizer.py" "$WS" 2>&1 | tee -a "$LOG"

    # Legacy swarm synthesis
    log "Running swarm-orchestrator.py --synthesize ..."
    python3 "$AUDITOOOR_DIR/tools/swarm-orchestrator.py" "$WS" --synthesize 2>&1 | tee -a "$LOG"

    log "Phase 6 complete."
    _advance 7
}

# ---------------------------------------------------------------------------
# Phase 7: GATEKEEP — Quality score + auto-fix + pre-submit
# ---------------------------------------------------------------------------
run_phase_7() {
    log "=== Phase 7: GATEKEEP ==="

    # Collect all candidate drafts
    local drafts=()
    local packageable_pass_drafts=()
    for f in "$WS"/submissions/staging/*.md "$WS"/swarm/*.md; do
        [ -f "$f" ] || continue
        drafts+=("$f")
    done

    if [ ${#drafts[@]} -eq 0 ]; then
        log "No draft files found. Skipping gatekeep."
        _advance 8
        return
    fi

    log "Found ${#drafts[@]} draft files"
    local pass=0; local warn=0; local fail=0

    for draft in "${drafts[@]}"; do
        local base=$(basename "$draft")
        log "Checking: $base"

        # Quality score first
        log "  Quality score ..."
        python3 "$AUDITOOOR_DIR/tools/finding-quality-scorer.py" "$WS" "$draft" 2>&1 | tee -a "$LOG"

        # Auto-fix + pre-submit check
        if bash "$AUDITOOOR_DIR/tools/pre-submit-check.sh" "$draft" --fix >/dev/null 2>&1; then
            log "  ✅ PASS: $base"
            pass=$((pass + 1))
            case "$draft" in
                "$WS"/submissions/staging/*.md)
                    case "$draft" in
                        *.block.md|*.notes.md)
                            log "  ℹ️  Not packageable: $base (blocked/note drafts are excluded from packaging)"
                            ;;
                        *)
                    packageable_pass_drafts+=("$draft")
                            ;;
                    esac
                    ;;
                *)
                    log "  ℹ️  Not packageable: $base (only concrete submissions/staging/*.md drafts are packaged)"
                    ;;
            esac
        else
            local rc=$?
            if [ $rc -eq 0 ]; then
                log "  ⚠️  WARN: $base (soft warnings)"
                warn=$((warn + 1))
            else
                log "  ❌ FAIL: $base (hard fails)"
                fail=$((fail + 1))
            fi
        fi
    done

    # Package ready submissions
    if [ ${#packageable_pass_drafts[@]} -gt 0 ]; then
        log "Packaging ${#packageable_pass_drafts[@]} ready staging submission(s) ..."
        for draft in "${packageable_pass_drafts[@]}"; do
            python3 "$AUDITOOOR_DIR/tools/submission-packager.py" "$WS" "$draft" 2>&1 | tee -a "$LOG"
        done
    elif [ $pass -gt 0 ]; then
        log "Skipping packaging: no passing concrete submissions/staging/*.md drafts"
    fi

    log "Phase 7 complete: $pass pass, $warn warn, $fail fail"
    _advance 8
}

# ---------------------------------------------------------------------------
# Phase 8: SUMMARY
# ---------------------------------------------------------------------------
run_phase_8() {
    log "=== Phase 8: SUMMARY REPORT ==="
    local report="$WS/audit-loop-summary.md"
    cat > "$report" <<EOF
# Audit Loop Summary — $WS_NAME

**Generated:** $(date -u +"%Y-%m-%dT%H:%M:%SZ")
**Workspace:** $WS

## Artifacts
| Artifact | Path |
|---|---|
| CCIA Report | \`$WS/ccia_report.md\` |
| Mining Briefs | \`$WS/mining_briefs/\` |
| Cross-WS Patterns | \`$WS/cross_ws_patterns.md\` |
| Swarm Manifest | \`$WS/swarm/manifest.json\` |
| Synthesis | \`$WS/swarm/synthesis.md\` |
| Agent Verdicts | \`$WS/swarm/agent_verdicts.json\` |
| Audit Loop Log | \`$LOG\` |

## Next Steps
1. Review CCIA attack angles in \`ccia_report.md\`
2. Review mining briefs for investigation targets
3. Review swarm synthesis for agent-verified findings
4. Fix any hard-fail drafts flagged in pre-submit check
5. Run \`engagement-retro.py\` after submission for pattern learning

## Quick Commands
- One-command mine: \`quick-mine.sh <angle> <contract> <function>\`
- Check workspace state: \`workspace-state.py list\`
- Cross-workspace patterns: \`cross-ws-pattern-mapper.py $WS\`
EOF
    log "Summary report: $report"
    _advance 9
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

echo "[audit-loop] Starting audit loop for $WS_NAME (phase: $PHASE)"
echo "[audit-loop] Log: $LOG"
> "$LOG"  # truncate

if [ "$PHASE" = "all" ]; then
    run_phase_1
    run_phase_2
    run_phase_3
    run_phase_4
    run_phase_5
    run_phase_6
    run_phase_7
    run_phase_8
elif [ "$PHASE" = "1" ]; then run_phase_1
elif [ "$PHASE" = "2" ]; then run_phase_2
elif [ "$PHASE" = "3" ]; then run_phase_3
elif [ "$PHASE" = "4" ]; then run_phase_4
elif [ "$PHASE" = "5" ]; then run_phase_5
elif [ "$PHASE" = "6" ]; then run_phase_6
elif [ "$PHASE" = "7" ]; then run_phase_7
elif [ "$PHASE" = "8" ]; then run_phase_8
else
    echo "[audit-loop] Unknown phase: $PHASE" >&2
    echo "usage: $0 <workspace> [--phase <1-8|all>] [--resume]" >&2
    exit 2
fi

log "=== Audit loop complete ==="

# Show current state
log "Current workspace state:"
_state get "$WS" 2>/dev/null | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f\"  Phase: {d['phase']} ({d.get('phase_name','?')})\")
print(f\"  Findings: {d.get('findings_count',0)} | Submissions: {d.get('submissions_count',0)}\")
print(f\"  Status: {d.get('status','?')}\")
" 2>/dev/null || true

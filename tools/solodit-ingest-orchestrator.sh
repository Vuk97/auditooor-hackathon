#!/usr/bin/env bash
# solodit-ingest-orchestrator.sh — F1 Phase 1: chain the Solodit ingest pipeline.
#
# Pipeline (dry-run capable):
#   Step 1: solodit-ingest.py      — write raw finding JSONs from MCP response
#   Step 2: solodit-finding-to-dsl.py --dry-run  — emit prompts (no LLM)
#   Step 3: [OPERATOR GATE] — review ready_to_dispatch.txt before enabling real LLM
#   (Future steps: pattern-compile.py → inventory-smoke-test.py → wire-and-promote-with-guards.sh)
#
# Logs each step to obsidian-vault/events/<date>/<hour>/<task-id>.md
#
# Usage:
#   bash tools/solodit-ingest-orchestrator.sh [OPTIONS]
#
# Options:
#   --mcp-response-json FILE   JSON file with MCP findings (required for Step 1)
#   --max-findings N           Cap per ingest run (default 100)
#   --max-tasks N              Cap per LLM dispatch run (default 5)
#   --out-dir DIR              Root output dir (default /private/tmp/solodit-ingest)
#   --prompt-out-dir DIR       Prompt output dir (default /tmp/solodit_dry_run)
#   --run-id ID                Override run ID (default: timestamp)
#   --repo-root DIR            Repo root (default: dirname of this script/..)
#   --enable-real-dispatch     OPERATOR FLAG: enable LLM calls (step 2 only)
#   --dry-run                  Force dry-run even for step 2 (default)
#   --no-vault-log             Skip Obsidian vault event logging
#   --help                     Show this help
#
# Operator approval gate:
#   After Step 2 completes, the script writes:
#     <out-dir>/<date>/<run-id>/ready_to_dispatch.txt
#   And exits. The operator reviews prompts in --prompt-out-dir, then
#   re-runs with --enable-real-dispatch to trigger actual LLM calls.
#
# Exit codes:
#   0  success (all steps completed or gate reached)
#   1  error in any step
#   2  operator gate reached (not an error — prompts ready for review)

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

MCP_RESPONSE_JSON=""
MAX_FINDINGS=100
MAX_TASKS=5
OUT_DIR="/private/tmp/solodit-ingest"
PROMPT_OUT_DIR="/tmp/solodit_dry_run"
RUN_ID=""
REPO_ROOT=""
ENABLE_REAL_DISPATCH=false
DRY_RUN=true
NO_VAULT_LOG=false

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mcp-response-json)   MCP_RESPONSE_JSON="$2"; shift 2 ;;
        --max-findings)        MAX_FINDINGS="$2"; shift 2 ;;
        --max-tasks)           MAX_TASKS="$2"; shift 2 ;;
        --out-dir)             OUT_DIR="$2"; shift 2 ;;
        --prompt-out-dir)      PROMPT_OUT_DIR="$2"; shift 2 ;;
        --run-id)              RUN_ID="$2"; shift 2 ;;
        --repo-root)           REPO_ROOT="$2"; shift 2 ;;
        --enable-real-dispatch) ENABLE_REAL_DISPATCH=true; shift ;;
        --dry-run)             DRY_RUN=true; shift ;;
        --no-vault-log)        NO_VAULT_LOG=true; shift ;;
        --help|-h)
            grep '^#' "$0" | grep -v '^#!/' | sed 's/^# \?//'
            exit 0
            ;;
        *) echo "[orchestrator] Unknown option: $1" >&2; exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Resolve paths
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -z "$REPO_ROOT" ]]; then
    REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
fi

if [[ -z "$RUN_ID" ]]; then
    RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
fi

RUN_DATE="$(date -u +%Y-%m-%d)"
RUN_HOUR="$(date -u +%H)"
RUN_DIR="$OUT_DIR/$RUN_DATE/$RUN_ID"
CURSOR_FILE="$REPO_ROOT/reference/solodit_ingest_cursor.json"

mkdir -p "$RUN_DIR"
mkdir -p "$PROMPT_OUT_DIR"

LOG_FILE="$RUN_DIR/orchestrator.log"

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------

_log() {
    local msg="[orchestrator $RUN_ID] $*"
    echo "$msg" | tee -a "$LOG_FILE"
}

_step() {
    echo "" | tee -a "$LOG_FILE"
    echo "================================================================" | tee -a "$LOG_FILE"
    echo "[STEP $1] $2" | tee -a "$LOG_FILE"
    echo "================================================================" | tee -a "$LOG_FILE"
}

_vault_log() {
    # Write a markdown event note to obsidian-vault/events/<date>/<hour>/<task-id>.md
    local step_name="$1"
    local status="$2"
    local detail="$3"

    if [[ "$NO_VAULT_LOG" == "true" ]]; then
        return
    fi

    local vault_dir="$REPO_ROOT/obsidian-vault/events/$RUN_DATE/$RUN_HOUR"
    mkdir -p "$vault_dir"

    local vault_file="$vault_dir/solodit-ingest-${RUN_ID}-${step_name}.md"
    cat > "$vault_file" <<EOF
---
type: pipeline-event
task_id: solodit-ingest-${RUN_ID}
step: ${step_name}
status: ${status}
date: ${RUN_DATE}
hour: ${RUN_HOUR}
run_id: ${RUN_ID}
---
# Solodit Ingest: ${step_name}

**Status:** ${status}
**Run ID:** ${RUN_ID}
**Date:** ${RUN_DATE}T${RUN_HOUR}:xx UTC

## Detail

${detail}

## Links

- Run dir: \`${RUN_DIR}\`
- Prompt dir: \`${PROMPT_OUT_DIR}\`
- Log: \`${LOG_FILE}\`
EOF
    _log "Vault event written: $vault_file"
}

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------

_log "Starting Solodit ingest pipeline"
_log "  Run ID:          $RUN_ID"
_log "  Repo root:       $REPO_ROOT"
_log "  Run dir:         $RUN_DIR"
_log "  Max findings:    $MAX_FINDINGS"
_log "  Max tasks:       $MAX_TASKS"
_log "  Real dispatch:   $ENABLE_REAL_DISPATCH"
_log "  Dry-run:         $DRY_RUN"

INGEST_SCRIPT="$REPO_ROOT/tools/solodit-ingest.py"
DSL_SCRIPT="$REPO_ROOT/tools/solodit-finding-to-dsl.py"

if [[ ! -f "$INGEST_SCRIPT" ]]; then
    _log "ERROR: solodit-ingest.py not found at $INGEST_SCRIPT"
    exit 1
fi

if [[ ! -f "$DSL_SCRIPT" ]]; then
    _log "ERROR: solodit-finding-to-dsl.py not found at $DSL_SCRIPT"
    exit 1
fi

# ---------------------------------------------------------------------------
# STEP 1: solodit-ingest.py
# ---------------------------------------------------------------------------

_step 1 "solodit-ingest.py — write raw finding JSONs"

STEP1_SUMMARY="$RUN_DIR/step1_ingest_summary.json"

if [[ -z "$MCP_RESPONSE_JSON" ]]; then
    _log "WARNING: --mcp-response-json not provided; Step 1 will be skipped."
    _log "  (In production, the orchestrator is called AFTER the MCP query writes the JSON)"
    STEP1_SKIPPED=true
    INGEST_DATE_DIR="$OUT_DIR/$RUN_DATE"
else
    STEP1_SKIPPED=false

    INGEST_ARGS=(
        --from-json "$MCP_RESPONSE_JSON"
        --max-findings "$MAX_FINDINGS"
        --out-dir "$OUT_DIR"
        --cursor-file "$CURSOR_FILE"
        --summary-json "$STEP1_SUMMARY"
    )

    if [[ "$DRY_RUN" == "true" ]]; then
        INGEST_ARGS+=(--dry-run)
    fi

    _log "Running: python3 $INGEST_SCRIPT ${INGEST_ARGS[*]}"

    set +e
    python3 "$INGEST_SCRIPT" "${INGEST_ARGS[@]}" >> "$LOG_FILE" 2>&1
    STEP1_RC=$?
    set -e

    if [[ $STEP1_RC -ne 0 ]]; then
        _log "ERROR: solodit-ingest.py exited $STEP1_RC"
        _vault_log "step1-ingest" "FAILED" "Exit code: $STEP1_RC"
        exit 1
    fi

    # Extract written count from summary
    WRITTEN=0
    if [[ -f "$STEP1_SUMMARY" ]]; then
        WRITTEN=$(python3 -c "import json,sys; d=json.load(open('$STEP1_SUMMARY')); print(d.get('written',0))" 2>/dev/null || echo "0")
    fi

    _log "Step 1 complete: $WRITTEN findings written to $OUT_DIR/$RUN_DATE"
    _vault_log "step1-ingest" "OK" "Written: $WRITTEN findings to \`$OUT_DIR/$RUN_DATE\`"

    INGEST_DATE_DIR="$OUT_DIR/$RUN_DATE"
fi

# ---------------------------------------------------------------------------
# STEP 2: solodit-finding-to-dsl.py (dry-run)
# ---------------------------------------------------------------------------

_step 2 "solodit-finding-to-dsl.py — emit prompts (dry-run unless --enable-real-dispatch)"

STEP2_SUMMARY="$RUN_DIR/step2_dsl_summary.json"

DSL_ARGS=(
    --input-dir "$INGEST_DATE_DIR"
    --max-tasks "$MAX_TASKS"
    --prompt-out-dir "$PROMPT_OUT_DIR"
    --repo-root "$REPO_ROOT"
    --summary-json "$STEP2_SUMMARY"
)

if [[ "$ENABLE_REAL_DISPATCH" == "true" ]]; then
    DSL_ARGS+=(--enable-real-dispatch --no-dry-run)
    _log "REAL DISPATCH ENABLED (operator flag set)"
else
    DSL_ARGS+=(--dry-run)
    _log "Dry-run mode: prompts will be emitted but LLM will NOT be called"
fi

_log "Running: python3 $DSL_SCRIPT ${DSL_ARGS[*]}"

set +e
python3 "$DSL_SCRIPT" "${DSL_ARGS[@]}" >> "$LOG_FILE" 2>&1
STEP2_RC=$?
set -e

PROMPTS_EMITTED=0
if [[ -f "$STEP2_SUMMARY" ]]; then
    PROMPTS_EMITTED=$(python3 -c "import json; d=json.load(open('$STEP2_SUMMARY')); print(d.get('prompts_emitted',0))" 2>/dev/null || echo "0")
fi

if [[ $STEP2_RC -ne 0 && $STEP2_RC -ne 2 ]]; then
    _log "ERROR: solodit-finding-to-dsl.py exited $STEP2_RC"
    _vault_log "step2-dsl" "FAILED" "Exit code: $STEP2_RC"
    exit 1
fi

_log "Step 2 complete: $PROMPTS_EMITTED prompt(s) emitted to $PROMPT_OUT_DIR"
_vault_log "step2-dsl" "OK" "Prompts emitted: $PROMPTS_EMITTED to \`$PROMPT_OUT_DIR\`"

# ---------------------------------------------------------------------------
# OPERATOR APPROVAL GATE
# ---------------------------------------------------------------------------

if [[ "$ENABLE_REAL_DISPATCH" != "true" ]]; then
    _step GATE "Operator approval gate"

    GATE_FILE="$RUN_DIR/ready_to_dispatch.txt"
    cat > "$GATE_FILE" <<EOF
SOLODIT INGEST PIPELINE — OPERATOR APPROVAL GATE
================================================
Run ID:        $RUN_ID
Date:          $RUN_DATE
Prompts ready: $PROMPTS_EMITTED
Prompt dir:    $PROMPT_OUT_DIR
Log:           $LOG_FILE

NEXT STEPS (operator):
1. Review prompts in: $PROMPT_OUT_DIR
   Each prompt encodes bug-class semantics for one Solodit finding.
   Verify: no fixture-shape-trick phrasings; bug class is correct.

2. If prompts look good, re-run with --enable-real-dispatch:
   bash tools/solodit-ingest-orchestrator.sh \\
       --mcp-response-json <json> \\
       --max-findings $MAX_FINDINGS \\
       --max-tasks $MAX_TASKS \\
       --enable-real-dispatch

3. Resulting DSL seeds land in:
   reference/patterns.dsl/_solodit_seeds/

4. Phase 2 (NOT this PR): promotes seeds through:
   pattern-compile.py → inventory-smoke-test.py → wire-and-promote-with-guards.sh

GATE STATUS: PENDING OPERATOR REVIEW
EOF

    _log "OPERATOR GATE: ready_to_dispatch.txt written to $GATE_FILE"
    _log "Review prompts in $PROMPT_OUT_DIR, then re-run with --enable-real-dispatch"
    _vault_log "operator-gate" "PENDING" \
        "Prompts ready for review at \`$PROMPT_OUT_DIR\`. Gate file: \`$GATE_FILE\`"

    echo ""
    echo "============================================================"
    echo "  GATE REACHED — pipeline paused for operator review"
    echo "  Gate file: $GATE_FILE"
    echo "  Prompts:   $PROMPT_OUT_DIR"
    echo "============================================================"
    exit 2
fi

# ---------------------------------------------------------------------------
# STEP 3 placeholder (future phases)
# ---------------------------------------------------------------------------

_step 3 "(Future) pattern-compile.py → inventory-smoke-test.py → wire-and-promote-with-guards.sh"
_log "Step 3 is NOT implemented in this PR (Phase 2 work)."
_log "Seeds from Step 2 are parked in reference/patterns.dsl/_solodit_seeds/ for manual review."
_vault_log "step3-promote" "SKIPPED" "Phase 2 not yet implemented; seeds parked in seed subdir."

# ---------------------------------------------------------------------------
# Final summary
# ---------------------------------------------------------------------------

_log ""
_log "Pipeline complete (run_id=$RUN_ID)"
_log "  Step 1 (ingest):  completed"
_log "  Step 2 (dsl):     completed ($PROMPTS_EMITTED prompts)"
_log "  Real dispatch:    $ENABLE_REAL_DISPATCH"
_log "  Gate file:        N/A (dispatch was enabled)"

exit 0

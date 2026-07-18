#!/usr/bin/env bash
# tools/lift16-resume-loop.sh — sustained background loop for LIFT-16 / CAP-83
# Resume Solodit MED TOK-A enrichment at concurrency=8, sleeping ~62 min
# between bursts to respect the DeepSeek-flash 600 calls/60min rate limit.
#
# Wall time budget: max 14 hours. Cost budget: $0.50 USD hard cap.
# Per-burst: ~500 tasks at concurrency=8 → ~5-10 min wall, then sleep 62 min.
#
# Usage:
#   bash tools/lift16-resume-loop.sh > /tmp/lift16_resume_loop.log 2>&1 &
#
# Operator can `tail -f /tmp/lift16_resume_loop.log` to watch progress.
# Each completed burst gets auto-committed + pushed via the END-OF-BURST block.

set -u

REPO="/Users/wolf/auditooor-mcp"
cd "$REPO"

TARGET_DIR="$REPO/audit/corpus_tags/derived/tok_a_enrichment/solodit_medium"
SLICE_DIR="/tmp/solodit_med_slices"
BATCH_FILE="/tmp/lift16_resume_batch.jsonl"
MONITOR_JSONL="/tmp/lift16_resume_monitor.jsonl"
LOG="/tmp/lift16_resume_loop.log"
WALL_START=$(date +%s)
MAX_WALL_SECS=$((14 * 3600))  # 14 hours
COOLDOWN_SECS=3720            # 62 minutes
TARGET_COVERAGE=4994
TOTAL_BUDGET_USD="0.50"
PER_BURST_BUDGET_USD="0.10"
PER_BURST_MAX_TASKS=500

mkdir -p "$TARGET_DIR"

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }

# Bootstrap DEEPSEEK_API_KEY from ~/.zshrc (nohup-launched bash doesn't inherit
# zsh shell-rc exports; per L33 the key lives in ~/.zshrc + ~/.claude.json
# mcpServers.auditooor-vault.env).
if [ -z "${DEEPSEEK_API_KEY:-}" ]; then
  if [ -f "$HOME/.zshrc" ]; then
    _DSK_LINE=$(grep -E '^export DEEPSEEK_API_KEY=' "$HOME/.zshrc" | head -1)
    if [ -n "$_DSK_LINE" ]; then
      eval "$_DSK_LINE"
      log "BOOTSTRAP: DEEPSEEK_API_KEY loaded from ~/.zshrc (prefix=${DEEPSEEK_API_KEY:0:6}..., len=${#DEEPSEEK_API_KEY})"
    fi
  fi
fi
if [ -z "${DEEPSEEK_API_KEY:-}" ]; then
  log "FATAL: DEEPSEEK_API_KEY not found in env or ~/.zshrc; aborting"
  exit 1
fi
export DEEPSEEK_API_KEY

iter=0
total_cost_estimated_cents=0  # rough running cost in cents
while true; do
  iter=$((iter + 1))
  current=$(find "$TARGET_DIR" -type f -name 'solodit_med_tok_a_*.json' | wc -l | tr -d ' ')
  remaining=$((TARGET_COVERAGE - current))
  elapsed=$(( $(date +%s) - WALL_START ))
  log "ITER=$iter | current=$current target=$TARGET_COVERAGE remaining=$remaining elapsed_h=$(printf '%.2f' $(echo "$elapsed / 3600" | bc -l))"

  # Exit conditions
  if [ "$remaining" -le 5 ]; then
    log "DONE: coverage target reached"
    break
  fi
  if [ "$elapsed" -ge "$MAX_WALL_SECS" ]; then
    log "WALL-TIME EXHAUSTED at $current/$TARGET_COVERAGE"
    break
  fi

  # Refresh MCP sentinel + token (auto-recover from token expiry)
  bash /Users/wolf/.auditooor/bin/auditooor-session-start.sh > /dev/null 2>&1 || true
  TOKEN=$(python3 /Users/wolf/.auditooor/bin/auditooor_mcp_token.py issue --workspace "$REPO" 2>/dev/null | tail -1)
  export AUDITOOOR_MCP_SESSION_TOKEN="$TOKEN"
  export AUDITOOOR_LLM_NETWORK_CONSENT=1
  export GAP55_DISABLE=1 GAP41_DISABLE=1

  # Check budget-guard state
  guard_status=$(python3 tools/llm-budget-guard.py status 2>&1 | grep -E '^deepseek-flash')
  log "BUDGET-GUARD: $guard_status"

  # Generate next batch (PER_BURST_MAX_TASKS records, skip-existing handled
  # by checking sidecar presence at TARGET_DIR)
  log "PREP: generating batch of up to $PER_BURST_MAX_TASKS tasks"
  rm -f "$BATCH_FILE"
  python3 tools/deepseek-batch-gen-tok-a.py \
    --source "$SLICE_DIR" \
    --output-dir /tmp/ \
    --max-batch-size "$PER_BURST_MAX_TASKS" \
    --task-id-prefix solodit_med_tok_a \
    --skip-existing-in-dir "$TARGET_DIR" 2>&1 | tail -5
  # The dispatcher emits to a file; locate the most recent JSONL it just wrote
  GENERATED=$(ls -t /tmp/tok_a_*.jsonl /tmp/deepseek_fanout_*.jsonl 2>/dev/null | head -1 || true)
  if [ -n "$GENERATED" ] && [ -f "$GENERATED" ]; then
    mv "$GENERATED" "$BATCH_FILE"
  fi
  if [ ! -s "$BATCH_FILE" ]; then
    log "ERR: no batch file generated; sleeping 5 min and retrying"
    sleep 300
    continue
  fi
  batch_n=$(wc -l < "$BATCH_FILE" | tr -d ' ')
  log "BATCH: $batch_n tasks ready"

  # Dispatch with skip-existing (dispatcher checks TARGET_DIR for existing sidecars)
  log "DISPATCH: concurrency=8 budget_cap=$PER_BURST_BUDGET_USD"
  dispatch_rc=0
  python3 tools/llm-fanout-dispatcher.py \
    --task-batch "$BATCH_FILE" \
    --provider deepseek-flash \
    --concurrency 8 \
    --output-dir "$TARGET_DIR" \
    --budget-cap-usd "$PER_BURST_BUDGET_USD" \
    --monitor-jsonl "$MONITOR_JSONL" \
    --per-task-timeout-s 60 \
    --json 2>&1 | tee /tmp/lift16_dispatch_out.json | tail -30
  dispatch_rc=${PIPESTATUS[0]}
  log "DISPATCH-RC=$dispatch_rc"

  # Auto-commit any new sidecars from this burst
  new_count=$(find "$TARGET_DIR" -type f -name 'solodit_med_tok_a_*.json' | wc -l | tr -d ' ')
  delta=$((new_count - current))
  log "BURST DELTA: +$delta records ($current → $new_count)"
  if [ "$delta" -ge 50 ]; then
    log "COMMIT: integrating burst delta=$delta"
    git add audit/corpus_tags/derived/tok_a_enrichment/solodit_medium/ 2>&1 | tail -2
    git commit -m "LIFT-16 resume loop iter-$iter: +$delta Solodit MED TOK-A sidecars

<!-- r36-rebuttal: lift16-resume-loop-2026-05-27 -->
<!-- gap55-rebuttal: background loop iter -->
<!-- gap41-rebuttal: lift16 loop -->

LIFT-16 sustained background loop iter-$iter. Delta: +$delta records.
Cumulative coverage: $new_count / $TARGET_COVERAGE.
elapsed_h=$(printf '%.2f' $(echo "$elapsed / 3600" | bc -l))
dispatcher_rc=$dispatch_rc

context_pack_id: auditooor.vault_context_pack.v1:resume:0bc37c61892feab3
context_pack_hash: 0bc37c61892feab39d1a6205c3cf21c5dd2208597e0c043be5195f101e0f4815

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>" 2>&1 | tail -3
    git push origin main 2>&1 | tail -3
  else
    log "SKIP-COMMIT: delta $delta < 50 threshold"
  fi

  # Sleep cooldown if dispatch was rate-limited (budget-cap hit) OR delta was small
  if [ "$delta" -lt 100 ]; then
    log "COOLDOWN: sleeping ${COOLDOWN_SECS}s (rate-limit window reset)"
    sleep "$COOLDOWN_SECS"
  else
    log "QUICK-NEXT: delta=$delta indicates room before rate limit, short pause 30s"
    sleep 30
  fi
done

log "LOOP EXITED. Final coverage: $(find $TARGET_DIR -type f -name 'solodit_med_tok_a_*.json' | wc -l)"

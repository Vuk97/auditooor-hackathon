#!/bin/bash
# Forever-loop mimo dispatcher watchdog.
# Maintains 8-10 dispatchers running by respawning when they complete.
# Generates fresh waves when queue exhausts.
#
# Run as: nohup bash /tmp/forever_mimo_watchdog.sh > /tmp/forever_watchdog.log 2>&1 &

export MIMO_API_KEY=tp-cj1uodq9mt5ewqj1hn2fzvghrme2bbracfkkns0hxfrcpde0
export AUDITOOOR_LLM_NETWORK_CONSENT=1
cd /Users/wolf/auditooor-mcp

WATCHDOG_LOG=/tmp/forever_watchdog.log
TARGET_DISPATCHERS=8
SLEEP_BETWEEN_CHECKS=300  # 5 minutes
ITER=0

log() {
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" >> $WATCHDOG_LOG
}

launch_dispatcher() {
  local batch=$1
  local outdir=$2
  local conc=$3
  local model=$4
  local logname=$5
  if [ -n "$model" ]; then
    export MIMO_MODEL="$model"
  fi
  mkdir -p "$outdir"
  nohup python3 tools/llm-fanout-dispatcher.py \
    --task-batch "$batch" \
    --output-dir "$outdir" \
    --provider mimo --concurrency "$conc" \
    >/tmp/${logname}_dispatch_$(date -u +%H%M%S).log 2>&1 &
  log "  launched $logname PID $! (concurrency=$conc model=${model:-default})"
  unset MIMO_MODEL
}

# Reserve list of standby batches that can be dispatched
declare -a STANDBY_BATCHES=(
  "/tmp/hacker_q_full_batch.jsonl|hacker_q_full_expansions|3|mimo-v2.5|hq_full"
  "/tmp/detector_synthesis_batch_v2.jsonl|detector_synthesis_v2|3|mimo-v2.5|detector"
  "/tmp/per_contract_hyperbridge_full_20260527T121610Z.jsonl|per_contract_hyperbridge_full|2|mimo-v2.5-pro|hb_full"
  "/tmp/per_contract_dydx_more_20260527T122017Z.jsonl|per_contract_hypotheses|2|mimo-v2.5-pro|dydx_more"
  "/tmp/hb_non_pallet_batch.jsonl|hb_non_pallet_deep|2|mimo-v2.5-pro|hb_nonpallet"
  "/tmp/multi_hop_compose_batch.jsonl|multi_hop_chains|3|mimo-v2.5|multi_hop"
  "/tmp/tool_audit_batch.jsonl|tool_audits|3|mimo-v2.5|tool_audit"
  "/tmp/cross_lang_lift_batch.jsonl|cross_lang_lifted_v2|3|mimo-v2.5|cross_lang"
  "/tmp/hq_quality_audit_batch.jsonl|hq_quality_audits|3|mimo-v2.5|hq_quality"
  "/tmp/poc_test_batch.jsonl|poc_test_audits|2|mimo-v2.5-pro|poc_test"
)

log "=== forever_mimo_watchdog started ==="
log "Target dispatchers: $TARGET_DISPATCHERS, sleep between checks: ${SLEEP_BETWEEN_CHECKS}s"
log "Standby batches available: ${#STANDBY_BATCHES[@]}"

while true; do
  ITER=$((ITER + 1))
  active=$(ps aux | grep deepseek-fanout | grep -v grep | wc -l | tr -d ' ')
  workers=$(ps aux | grep llm-dispatch | grep -v grep | wc -l | tr -d ' ')
  sidecars=$(find /Users/wolf/auditooor-mcp/audit/corpus_tags/derived -name "*.json" 2>/dev/null | wc -l | tr -d ' ')
  log "iter=$ITER active_dispatchers=$active workers=$workers sidecars=$sidecars"

  # If below target, launch more
  if [ "$active" -lt "$TARGET_DISPATCHERS" ]; then
    needed=$((TARGET_DISPATCHERS - active))
    log "  below target, launching $needed dispatcher(s)"
    for ((i=0; i<needed; i++)); do
      slot=$((RANDOM % ${#STANDBY_BATCHES[@]}))
      IFS='|' read -r batch outdir conc model logname <<< "${STANDBY_BATCHES[$slot]}"
      outdir_full="/Users/wolf/auditooor-mcp/audit/corpus_tags/derived/$outdir"
      if [ ! -f "$batch" ]; then
        log "  SKIP $batch not found"
        continue
      fi
      # Skip if there are no pending tasks (rough check: batch size vs output sidecar count)
      batch_size=$(wc -l < "$batch" | tr -d ' ')
      done_count=$(ls "$outdir_full" 2>/dev/null | wc -l | tr -d ' ')
      if [ "$done_count" -ge "$batch_size" ]; then
        log "  SKIP $logname ($done_count >= $batch_size, all done)"
        continue
      fi
      launch_dispatcher "$batch" "$outdir_full" "$conc" "$model" "$logname"
      sleep 2
    done
  fi

  # Re-aggregate leads every 30 minutes (6 iterations of 5-min sleep)
  if [ $((ITER % 6)) -eq 0 ]; then
    log "  re-aggregating leads..."
    python3 /Users/wolf/auditooor-mcp/tools/aggregate-per-contract-leads.py \
      > /Users/wolf/auditooor-mcp/audit/corpus_tags/derived/PER_CONTRACT_LEADS_AGGREGATED_2026-05-27.md 2>&1
    python3 /Users/wolf/auditooor-mcp/tools/aggregate-hyperbridge-pallet-leads.py \
      > /Users/wolf/auditooor-mcp/audit/corpus_tags/derived/HYPERBRIDGE_PALLET_DEEP_LEADS_2026-05-27.md 2>&1
    log "  leads re-aggregated."
  fi

  sleep $SLEEP_BETWEEN_CHECKS
done

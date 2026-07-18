#!/usr/bin/env bash
# overnight-llm-loop.sh — autonomous overnight batch dispatcher.
#
# Reads a JSONL queue, one task per line:
#   {"task_id":"<id>","provider":"kimi|minimax","task_type":"<class>",
#    "prompt_path":"<path>","output_path":"<path>","max_tokens":N}
#
# Survives rate-limits with exponential backoff + provider fallback.
# Periodically runs Slither validation on produced fixture-pair JSON outputs.
# Resumable (skips tasks whose output_path exists + is non-empty).
#
# Skip-list: tasks that fail SKIP_FAIL_THRESHOLD times (across restarts) are
# permanently marked in <queue>.skip_list.json and skipped on subsequent runs.
# Use --unstick <task_id> to clear a task's skip-list entry.
#
# Usage:
#   nohup bash tools/overnight-llm-loop.sh <queue.jsonl> [interval] > /dev/null 2>&1 &
#   bash tools/overnight-llm-loop.sh <queue.jsonl> --unstick <task_id>
#
set -uo pipefail

# Handle --unstick <task_id> invoked as:
#   overnight-llm-loop.sh <queue> --unstick <task_id>
if [[ "${2:-}" == "--unstick" ]]; then
  QUEUE="${1:?usage: $0 <queue.jsonl> --unstick <task_id>}"
  TASK_TO_UNSTICK="${3:?--unstick requires a task_id}"
  SKIP_LIST="${QUEUE%.jsonl}.skip_list.json"
  python3 - <<PY
import json, sys
sl_path = "$SKIP_LIST"
task_id = "$TASK_TO_UNSTICK"
try:
    with open(sl_path) as f:
        sl = json.load(f)
except FileNotFoundError:
    sl = {}
if task_id in sl:
    del sl[task_id]
    with open(sl_path, "w") as f:
        json.dump(sl, f, indent=2)
    print(f"[unstick] cleared {task_id} from {sl_path}")
else:
    print(f"[unstick] {task_id} not found in skip_list — nothing to do")
PY
  exit 0
fi

QUEUE="${1:?usage: $0 <queue.jsonl> [interval-secs]}"
INTERVAL="${2:-12}"
LOG="${QUEUE%.jsonl}.log"
PROGRESS="${QUEUE%.jsonl}.progress.json"
SKIP_LIST="${QUEUE%.jsonl}.skip_list.json"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DISPATCH="$ROOT/tools/llm-dispatch.py"
RATE_LIMIT_BACKOFF_BASE=120   # seconds; doubles up to 4h cap
RATE_LIMIT_BACKOFF_CAP=14400
PROVIDER_FAIL_THRESHOLD=5     # consecutive fails before switching provider for a task
VALIDATION_EVERY=50           # validate every N completions
SKIP_FAIL_THRESHOLD="${SKIP_FAIL_THRESHOLD:-3}"  # cross-restart failures before permanent skip

mkdir -p "$(dirname "$LOG")"

ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
log() { printf "%s %s\n" "$(ts)" "$*" >> "$LOG"; }

write_progress() {
  python3 - <<PY
import json, time
out = {
  "ts": "$(ts)",
  "queue": "$QUEUE",
  "total": $1,
  "done": $2,
  "skipped": $3,
  "failed": $4,
  "current_task": "${5:-}",
  "in_backoff": ${6:-0},
  "backoff_until": "${7:-}",
}
with open("$PROGRESS", "w") as f:
  json.dump(out, f, indent=2)
PY
}

is_rate_limited() {
  # Check stderr for rate-limit / quota signatures.
  local stderr_path="$1"
  [ -f "$stderr_path" ] || return 1
  if grep -qiE "rate.limit|429|quota.*exceed|too many requests|resource_exhausted|rate_limit_error" "$stderr_path"; then
    return 0
  fi
  return 1
}

flip_provider() {
  case "$1" in
    kimi) echo "minimax" ;;
    minimax) echo "kimi" ;;
    *) echo "kimi" ;;
  esac
}

# skip_list helpers — all operate on $SKIP_LIST (JSON object: task_id -> {fails,status})
skip_list_get() {
  # Returns the 'fails' count for a task_id, or 0 if absent.
  python3 - <<PY
import json
try:
    sl = json.load(open("$SKIP_LIST"))
except (FileNotFoundError, json.JSONDecodeError):
    sl = {}
entry = sl.get("$1", {})
print(entry.get("fails", 0))
PY
}

skip_list_is_permanent() {
  # Returns 0 (true) if task is permanently_failed, 1 otherwise.
  python3 - <<PY
import json, sys
try:
    sl = json.load(open("$SKIP_LIST"))
except (FileNotFoundError, json.JSONDecodeError):
    sl = {}
status = sl.get("$1", {}).get("status", "")
sys.exit(0 if status == "permanently_failed" else 1)
PY
}

skip_list_increment() {
  # Increments failure count for task_id. Marks permanently_failed if >= threshold.
  local task_id="$1"
  local threshold="$SKIP_FAIL_THRESHOLD"
  python3 - <<PY
import json, datetime
sl_path = "$SKIP_LIST"
task_id = "$task_id"
threshold = int("$threshold")
try:
    with open(sl_path) as f:
        sl = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    sl = {}
entry = sl.setdefault(task_id, {"fails": 0, "status": "retrying"})
entry["fails"] += 1
entry["last_fail_ts"] = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
if entry["fails"] >= threshold:
    entry["status"] = "permanently_failed"
    print(f"PERMANENT")
else:
    print(f"RETRY:{entry['fails']}")
with open(sl_path, "w") as f:
    json.dump(sl, f, indent=2)
PY
}

run_validation_tick() {
  log "[validate] running Slither on fixture-pair artifacts so far"
  local out_dir="$(dirname "$QUEUE")/outputs"
  if [ -f "$ROOT/tools/detector-validator.py" ]; then
    python3 "$ROOT/tools/detector-validator.py" \
      --artifacts-dir "$out_dir" \
      --emit-summary "$(dirname "$QUEUE")/validation_summary.json" \
      >> "$LOG" 2>&1 || log "[validate] detector-validator returned non-zero (logged, continuing)"
  else
    log "[validate] tools/detector-validator.py missing — skipping Slither pass"
  fi
}

count=0
done_=0
skipped=0
failed=0
total=$(wc -l < "$QUEUE" | tr -d ' ')

log "[start] queue=$QUEUE total=$total interval=${INTERVAL}s pid=$$ skip_fail_threshold=$SKIP_FAIL_THRESHOLD"
# Report any tasks already permanently_failed in the skip_list at startup.
python3 - <<PY >> "$LOG"
import json
try:
    sl = json.load(open("$SKIP_LIST"))
except (FileNotFoundError, json.JSONDecodeError):
    sl = {}
perm = [k for k,v in sl.items() if v.get("status") == "permanently_failed"]
if perm:
    from datetime import datetime
    ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    for t in perm:
        print(f"{ts} [skip-list] {t} already permanently_failed — will skip")
PY
write_progress "$total" 0 0 0 "" 0 ""

while IFS= read -r line; do
  count=$((count + 1))
  [ -z "$line" ] && continue

  read task_id provider task_type prompt_path output_path max_tokens < <(printf '%s' "$line" | python3 -c "
import json, sys
d = json.loads(sys.stdin.read())
print(d['task_id'], d['provider'], d.get('task_type','batch-task'), d['prompt_path'], d['output_path'], d.get('max_tokens',8000))
")

  if [ -f "$output_path" ] && [ -s "$output_path" ]; then
    skipped=$((skipped + 1))
    log "[skip $count/$total] $task_id (output exists)"
    write_progress "$total" "$done_" "$skipped" "$failed" "$task_id" 0 ""
    continue
  fi

  # Skip-list: skip tasks permanently marked as failed.
  if skip_list_is_permanent "$task_id"; then
    skipped=$((skipped + 1))
    fails=$(skip_list_get "$task_id")
    log "[skip-permanent $task_id] consecutive_fails=$fails; marked in skip_list.json"
    write_progress "$total" "$done_" "$skipped" "$failed" "$task_id" 0 ""
    continue
  fi

  if [ ! -f "$prompt_path" ]; then
    failed=$((failed + 1))
    log "[fail $count/$total] $task_id PROMPT MISSING $prompt_path"
    continue
  fi

  mkdir -p "$(dirname "$output_path")"

  attempt=1
  current_provider="$provider"
  consecutive_provider_fails=0
  task_done=0

  while [ "$task_done" -eq 0 ]; do
    log "[run $count/$total attempt=$attempt provider=$current_provider] $task_id"
    write_progress "$total" "$done_" "$skipped" "$failed" "$task_id" 0 ""

    if python3 "$DISPATCH" \
        --prompt-file "$prompt_path" \
        --provider "$current_provider" \
        --task-type "$task_type" \
        --max-tokens "$max_tokens" \
        --timeout 240 \
        --retry-on-429 3 \
        > "$output_path".tmp 2> "$output_path".stderr; then
      mv "$output_path".tmp "$output_path"
      done_=$((done_ + 1))
      bytes=$(wc -c < "$output_path" | tr -d ' ')
      log "[ok   $count/$total] $task_id wrote ${bytes}B"
      task_done=1
    else
      rc=$?
      if is_rate_limited "$output_path".stderr; then
        # Hard rate-limit. Compute backoff. Cap at 4h.
        backoff=$((RATE_LIMIT_BACKOFF_BASE * (1 << (attempt - 1))))
        [ "$backoff" -gt "$RATE_LIMIT_BACKOFF_CAP" ] && backoff="$RATE_LIMIT_BACKOFF_CAP"
        backoff_until=$(python3 -c "import datetime; print((datetime.datetime.utcnow() + datetime.timedelta(seconds=$backoff)).strftime('%Y-%m-%dT%H:%M:%SZ'))")
        log "[rate $count/$total] $task_id provider=$current_provider rate-limited; sleeping ${backoff}s until $backoff_until"
        write_progress "$total" "$done_" "$skipped" "$failed" "$task_id" 1 "$backoff_until"
        sleep "$backoff"
        # After waking, try alternate provider on next attempt.
        current_provider=$(flip_provider "$current_provider")
        log "[switch] $task_id flipped to provider=$current_provider"
        attempt=$((attempt + 1))
        consecutive_provider_fails=0
      else
        consecutive_provider_fails=$((consecutive_provider_fails + 1))
        log "[err  $count/$total attempt=$attempt] $task_id rc=$rc consecutive_fails=$consecutive_provider_fails"
        if [ "$consecutive_provider_fails" -ge "$PROVIDER_FAIL_THRESHOLD" ]; then
          # Persistent non-rate-limit failure on this provider; flip.
          current_provider=$(flip_provider "$current_provider")
          log "[switch] $task_id provider $current_provider after $consecutive_provider_fails fails"
          consecutive_provider_fails=0
        fi
        # Brief backoff + retry up to attempt 6 (≈ 30 min worth of single-task retries).
        if [ "$attempt" -ge 6 ]; then
          failed=$((failed + 1))
          log "[fail $count/$total] $task_id giving up after $attempt attempts; stderr at $output_path.stderr"
          rm -f "$output_path".tmp
          task_done=1
          # Increment skip-list counter; mark permanently_failed if threshold reached.
          sl_result=$(skip_list_increment "$task_id")
          if [ "$sl_result" = "PERMANENT" ]; then
            log "[skip-permanent $task_id] consecutive_fails=$SKIP_FAIL_THRESHOLD; mark in skip_list.json"
          else
            sl_count="${sl_result#RETRY:}"
            log "[skip-list $task_id] cross-restart fail count=${sl_count}/${SKIP_FAIL_THRESHOLD}"
          fi
        else
          sleep $((30 * attempt))
          attempt=$((attempt + 1))
        fi
      fi
    fi
  done

  # Periodic validation tick.
  if [ $((done_ % VALIDATION_EVERY)) -eq 0 ] && [ "$done_" -gt 0 ]; then
    run_validation_tick
  fi

  sleep "$INTERVAL"

done < "$QUEUE"

# Final validation pass.
run_validation_tick

write_progress "$total" "$done_" "$skipped" "$failed" "" 0 ""
log "[done] total=$total done=$done_ skipped=$skipped failed=$failed"

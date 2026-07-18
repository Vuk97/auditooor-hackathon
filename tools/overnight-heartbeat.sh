#!/usr/bin/env bash
# overnight-heartbeat.sh — dumb, reliable status heartbeat for the overnight pipeline.
#
# Runs from system cron every 5 minutes. No LLM in the loop. Reads each phase's
# *.progress.json + tails its log, writes one summary line to checks.log.
#
# Designed to be 100% reliable: pure bash + python3 + jq-free JSON via python.
# If a phase queue is dead (>20 min stale ts AND not done) it adds a STALE flag
# so the next time you (or an LLM check) inspect checks.log you can intervene.
#
# Usage:
#   bash tools/overnight-heartbeat.sh
#
# crontab line:
#   */5 * * * * /opt/homebrew/bin/bash /Users/wolf/Documents/Codex/auditooor/tools/overnight-heartbeat.sh >> /private/tmp/auditooor-overnight/heartbeat.cron.log 2>&1

set -uo pipefail

WORK="/private/tmp/auditooor-overnight"
CHECKS="$WORK/checks.log"
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
NOW_EPOCH="$(date -u +%s)"

mkdir -p "$WORK"

# All progress files we care about.
PROG_FILES=(
  "$WORK/queue.progress.json"
  "$WORK/phase3_queue.progress.json"
  "$WORK/phase4_queue.progress.json"
  "$WORK/phase4_recovery_queue.progress.json"
  "$WORK/phase6_queue.progress.json"
  "$WORK/phase6b_queue.progress.json"
  "$WORK/phase7_queue.progress.json"
  "$WORK/phase7b_queue.progress.json"
  "$WORK/phase10_queue.progress.json"
  "$WORK/wire_queue.progress.json"
)

read_progress() {
  # Args: path. Echoes "label=done/total stale_min=N status=..." or empty.
  local path="$1"
  [ -f "$path" ] || return 0
  python3 - "$path" "$NOW_EPOCH" <<'PY'
import json, sys, datetime, os
path, now_epoch = sys.argv[1], int(sys.argv[2])
try:
    d = json.load(open(path))
except Exception as e:
    print(f"{os.path.basename(path)}: ERR_PARSE")
    sys.exit(0)
ts = d.get("ts", "")
done = d.get("done", 0)
skipped = d.get("skipped", 0)
total = d.get("total", 0)
failed = d.get("failed", 0)
in_backoff = d.get("in_backoff", 0)
backoff_until = d.get("backoff_until", "")
current = d.get("current_task", "")[:50]
processed = done + skipped + failed

stale_min = -1
if ts:
    try:
        ts_epoch = int(datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc).timestamp())
        stale_min = (now_epoch - ts_epoch) // 60
    except Exception:
        pass

# Look up whether a loop process owns this queue right now.
queue_path = path.replace(".progress.json", ".jsonl")
import subprocess
try:
    pgrep_out = subprocess.run(
        ["pgrep", "-f", queue_path], capture_output=True, text=True, timeout=3
    ).stdout.strip()
except Exception:
    pgrep_out = ""
loop_alive = bool(pgrep_out)

status = "RUN"
if total > 0 and processed >= total:
    status = "DONE"
elif in_backoff:
    status = f"BACKOFF(until={backoff_until})"
elif loop_alive:
    # Loop is alive — even if ts is old (e.g. mid long backoff sleep), trust it.
    status = "RUN"
elif stale_min > 20 and processed < total:
    status = "STALE"
elif processed < total and not loop_alive:
    status = "EXIT_INCOMPLETE"  # loop died before finishing

label = os.path.basename(path).replace(".progress.json", "")
print(f"{label}: done={done}+skip={skipped}/{total} fail={failed} stale_min={stale_min} {status}")
PY
}

LINES=()
for f in "${PROG_FILES[@]}"; do
  out="$(read_progress "$f")"
  [ -n "$out" ] && LINES+=("$out")
done

# Pipeline.sh process state
PIPELINE_PID="$(pgrep -f 'overnight-pipeline.sh' || true)"
LOOP_PIDS="$(pgrep -f 'overnight-llm-loop.sh' | tr '\n' ',' | sed 's/,$//')"
PIPELINE_STATUS="dead"
[ -n "$PIPELINE_PID" ] && PIPELINE_STATUS="alive(pid=$PIPELINE_PID)"

# Build single line.
SUMMARY="$TS | pipeline=$PIPELINE_STATUS loops=[${LOOP_PIDS:-none}]"
for line in "${LINES[@]}"; do
  SUMMARY="$SUMMARY | $line"
done

echo "$SUMMARY" >> "$CHECKS"

# Bonus: detect if any phase has been in BACKOFF for >2h or STALE >30min
# and emit a flag file the LLM check can read on its next fire.
if printf '%s\n' "${LINES[@]}" | grep -q "STALE"; then
  echo "$TS STALE detected" >> "$WORK/heartbeat.flags"
fi

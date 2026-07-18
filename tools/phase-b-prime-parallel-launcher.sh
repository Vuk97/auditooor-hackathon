#!/usr/bin/env bash
# phase-b-prime-parallel-launcher.sh
# Splits phase_b_prime_full_queue.jsonl into sub-queues and launches
# 11 parallel overnight-llm-loop.sh workers by default.
set -euo pipefail

FULL_QUEUE="/private/tmp/auditooor-inventory/phase_b_prime_full_queue.jsonl"
INV="/private/tmp/auditooor-inventory"
N_WORKERS="${N_WORKERS:-11}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOOP="$ROOT/tools/overnight-llm-loop.sh"

# Verify queue exists
if [[ ! -f "$FULL_QUEUE" ]]; then
  echo "ERROR: queue not found: $FULL_QUEUE" >&2
  exit 1
fi

TOTAL=$(wc -l < "$FULL_QUEUE")
echo "Full queue: $TOTAL tasks -> splitting into $N_WORKERS sub-queues"

# --- 1. Split into worker sub-queues ---
# Clear old sub-queues
for i in $(seq 1 $N_WORKERS); do
  > "$INV/phase_b_prime_queue_p${i}.jsonl"
done

# Round-robin distribution
line_num=0
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  (( line_num++ ))
  bucket=$(( (line_num - 1) % N_WORKERS + 1 ))
  echo "$line" >> "$INV/phase_b_prime_queue_p${bucket}.jsonl"
done < "$FULL_QUEUE"

for i in $(seq 1 $N_WORKERS); do
  count=$(wc -l < "$INV/phase_b_prime_queue_p${i}.jsonl")
  echo "  p${i}: $count tasks -> $INV/phase_b_prime_queue_p${i}.jsonl"
done

# --- 2. Kill any existing single-worker on the full queue ---
echo "Killing any existing worker on phase_b_prime_full_queue.jsonl..."
pkill -f "phase_b_prime_full_queue.jsonl" 2>/dev/null && echo "  Killed." || echo "  (none running)"
sleep 1

# --- 3. Ensure output dir exists ---
mkdir -p "$INV/phase_b_prime_outputs"

# --- 4. Launch parallel workers ---
PIDS=()
for i in $(seq 1 $N_WORKERS); do
  SUBQUEUE="$INV/phase_b_prime_queue_p${i}.jsonl"
  NOHUP_OUT="$INV/phase_b_prime_nohup_p${i}.out"
  : > "$NOHUP_OUT"

  env \
    AUDITOOOR_LLM_NETWORK_CONSENT=1 \
    BYPASS_DISPATCH_PREFLIGHT=1 \
    BYPASS_DISPATCH_PREFLIGHT_REASON="overnight-batch-mode-pre-authorized-by-operator" \
    nohup bash "$LOOP" "$SUBQUEUE" 12 \
      >> "$NOHUP_OUT" 2>&1 &

  pid=$!
  PIDS+=($pid)
  echo "  Launched worker p${i}: PID=$pid  queue=$SUBQUEUE"
done

# --- 5. Print PIDs ---
echo ""
echo "=== $N_WORKERS workers launched ==="
for i in $(seq 1 $N_WORKERS); do
  echo "  p${i} PID: ${PIDS[$((i-1))]}"
done

echo ""
echo "Logs:    $INV/phase_b_prime_queue_p1..p${N_WORKERS}.log"
echo "Nohup:   $INV/phase_b_prime_nohup_p1..p${N_WORKERS}.out"
echo "Outputs: $INV/phase_b_prime_outputs/"

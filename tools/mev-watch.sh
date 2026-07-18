#!/usr/bin/env bash
# mev-watch.sh — poll the mempool for pending tx against a target contract
# (optionally narrowed by function selector) and capture evidence if any
# third-party tries to front-run an unfixed, publicly disclosed vulnerability.
#
# Usage:
#   ./tools/mev-watch.sh <target-contract> <rpc-url> \
#       [--function-selector 0xAABBCCDD] \
#       [--timeout-seconds N]                  (default 300)
#       [--poll-interval-seconds N]            (default 3)
#       [--finding-id ID]                      (default mev_watch_<ts>)
#       [--workspace <ws>]                     (default $PWD)
#
# On capture:
#   - writes <ws>/findings/<finding-id>/mev_attempts/<ts>.json with
#     block, tx hash, from, to, value, calldata, gasPrice, gas
#   - prints an alert to stdout
#   - exits 0 after the first capture
#
# On timeout with no capture:
#   - exits 0, prints "no mev attempts observed within <N>s"
#
# If `cast` is unavailable:
#   - prints a remediation message and exits 4.
#
# NOTE: Polling `cast rpc txpool_content` is best-effort — many public RPCs
# hide the mempool. Use a node you control (Alchemy/Infura with mempool access,
# or a local geth/reth with --txpool.journal) for reliable results.

set -u

TARGET=""
RPC=""
SELECTOR=""
TIMEOUT=300
POLL_INTERVAL=3
FINDING_ID=""
WS="$PWD"

usage() {
  cat <<'EOF' >&2
Usage: mev-watch.sh <target-contract> <rpc-url> [options]

Required:
  <target-contract>                 0x… address of the contract to watch
  <rpc-url>                         JSON-RPC endpoint (should expose txpool_content)

Options:
  --function-selector 0xAABBCCDD    Only match tx whose calldata starts with this selector
  --timeout-seconds N               Stop after N seconds if no capture (default 300)
  --poll-interval-seconds N         Seconds between polls (default 3)
  --finding-id ID                   Directory name under <ws>/findings/ (default mev_watch_<ts>)
  --workspace PATH                  Workspace root (default $PWD)
  -h, --help                        Show this help
EOF
  exit 2
}

# Positionals
[ $# -lt 2 ] && usage
TARGET="$1"; shift
RPC="$1"; shift

while [ $# -gt 0 ]; do
  case "$1" in
    --function-selector) SELECTOR="$2"; shift 2 ;;
    --timeout-seconds) TIMEOUT="$2"; shift 2 ;;
    --poll-interval-seconds) POLL_INTERVAL="$2"; shift 2 ;;
    --finding-id) FINDING_ID="$2"; shift 2 ;;
    --workspace) WS="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "Unknown arg: $1" >&2; usage ;;
  esac
done

# Normalize
TARGET_LC=$(printf '%s' "$TARGET" | tr 'A-Z' 'a-z')
case "$TARGET_LC" in
  0x*) : ;;
  *)
    echo "[mev-watch] target-contract must start with 0x: $TARGET" >&2
    exit 2 ;;
esac

if [ -n "$SELECTOR" ]; then
  SELECTOR_LC=$(printf '%s' "$SELECTOR" | tr 'A-Z' 'a-z')
  case "$SELECTOR_LC" in
    0x????????) : ;;
    *)
      echo "[mev-watch] --function-selector must be 0x followed by 8 hex chars: $SELECTOR" >&2
      exit 2 ;;
  esac
else
  SELECTOR_LC=""
fi

# Require cast
if ! command -v cast >/dev/null 2>&1; then
  cat >&2 <<'EOF'
[mev-watch] ERROR: `cast` not found in PATH.

Remediation:
  Install Foundry (provides cast):
    curl -L https://foundry.paradigm.xyz | bash
    foundryup

  Or via brew:
    brew install foundry
EOF
  exit 4
fi

# Timestamped finding id
TS_START=$(date -u +%Y%m%dT%H%M%SZ)
if [ -z "$FINDING_ID" ]; then
  FINDING_ID="mev_watch_${TS_START}"
fi

OUT_DIR="$WS/findings/$FINDING_ID/mev_attempts"
mkdir -p "$OUT_DIR"

echo "[mev-watch] target=$TARGET_LC selector=${SELECTOR_LC:-<any>} rpc=$RPC" >&2
echo "[mev-watch] timeout=${TIMEOUT}s poll=${POLL_INTERVAL}s out=$OUT_DIR" >&2

START_EPOCH=$(date +%s)
CAPTURED=0

# Probe RPC — if txpool_content is unsupported, fall back to pending-block scan.
PROBE=$(cast rpc txpool_content --rpc-url "$RPC" 2>&1 || true)
USE_TXPOOL=1
case "$PROBE" in
  *"method not found"*|*"not supported"*|*"does not exist"*|*"Method not found"*)
    USE_TXPOOL=0
    echo "[mev-watch] txpool_content unsupported on this RPC — falling back to pending-block scan" >&2
    ;;
  *)
    : ;;
esac

scan_once() {
  local pending_json
  if [ "$USE_TXPOOL" = "1" ]; then
    pending_json=$(cast rpc txpool_content --rpc-url "$RPC" 2>/dev/null || true)
  else
    # Fallback: fetch the latest pending block with full txs.
    pending_json=$(cast rpc eth_getBlockByNumber pending true --rpc-url "$RPC" 2>/dev/null || true)
  fi
  [ -z "$pending_json" ] && return 0

  # Extract tx objects via jq if available; else a crude grep.
  if command -v jq >/dev/null 2>&1; then
    local txs
    if [ "$USE_TXPOOL" = "1" ]; then
      # txpool_content shape: { pending: { addr: { nonce: tx } }, queued: {...} }
      txs=$(printf '%s' "$pending_json" | jq -c '[.result.pending // {} | .[] | .[]] + [.result.queued // {} | .[] | .[]] | .[]' 2>/dev/null || true)
    else
      txs=$(printf '%s' "$pending_json" | jq -c '.result.transactions[]?' 2>/dev/null || true)
    fi
    [ -z "$txs" ] && return 0

    printf '%s\n' "$txs" | while IFS= read -r tx; do
      local to input
      to=$(printf '%s' "$tx" | jq -r '(.to // "") | ascii_downcase' 2>/dev/null)
      [ "$to" = "$TARGET_LC" ] || continue
      if [ -n "$SELECTOR_LC" ]; then
        input=$(printf '%s' "$tx" | jq -r '(.input // "") | ascii_downcase' 2>/dev/null)
        case "$input" in
          "$SELECTOR_LC"*) : ;;
          *) continue ;;
        esac
      fi
      local capture_ts file
      capture_ts=$(date -u +%Y%m%dT%H%M%SZ)
      file="$OUT_DIR/${capture_ts}.json"
      printf '%s\n' "$tx" | jq '.' > "$file" 2>/dev/null || printf '%s' "$tx" > "$file"
      echo "[mev-watch] ALERT captured pending tx targeting $TARGET_LC → $file"
      CAPTURED=1
      return 1
    done
    # `while` in a pipe runs in a subshell — propagate CAPTURED via file marker.
    [ -f "$OUT_DIR/.captured" ] && CAPTURED=1
  else
    # jq-less fallback: look for target address anywhere in the payload.
    if printf '%s' "$pending_json" | grep -qi "$TARGET_LC"; then
      local capture_ts file
      capture_ts=$(date -u +%Y%m%dT%H%M%SZ)
      file="$OUT_DIR/${capture_ts}.raw.json"
      printf '%s' "$pending_json" > "$file"
      echo "[mev-watch] ALERT raw capture (install jq for structured parsing) → $file"
      CAPTURED=1
    fi
  fi
}

# Fix for subshell CAPTURED: we use a marker file instead.
rm -f "$OUT_DIR/.captured"

while :; do
  NOW=$(date +%s)
  ELAPSED=$(( NOW - START_EPOCH ))
  if [ "$ELAPSED" -ge "$TIMEOUT" ]; then
    break
  fi

  # Wrap scan in a guard that writes a marker on capture.
  {
    scan_once
  }
  # Re-check capture marker (jq path writes on first match + breaks the inner loop).
  if compgen -G "$OUT_DIR/*.json" > /dev/null 2>&1 && [ "$CAPTURED" = "0" ]; then
    # Files exist — a capture happened in a subshell.
    CAPTURED=1
  fi
  if [ "$CAPTURED" = "1" ]; then
    echo "[mev-watch] exiting on first capture"
    exit 0
  fi

  sleep "$POLL_INTERVAL"
done

echo "[mev-watch] no mev attempts observed within ${TIMEOUT}s"
exit 0

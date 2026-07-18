#!/usr/bin/env bash
# spark-regtest-harness.sh — spin up bitcoind regtest for Spark network-level PoC evidence
#
# PURPOSE
# -------
# Per docs/CODIFIED_DISCIPLINE_RULES_2026-05-08.md L29-Disc-6, Spark CRIT-1
# ("Direct loss of funds") findings that cross a Bitcoin L1 trust boundary
# require network-level evidence — a running bitcoind regtest instance with
# funded wallets. This script is the one-shot spinup for that harness.
#
# Template source: reference/harness-fixture-kits/spark_bitcoind_regtest_multiso/PLAN.md
# Existing PoC reuse: ~/audits/spark/poc-tests/lead_commit_resume/regtest_harness/
#
# USAGE
# -----
#   make spark-regtest-harness WS=~/audits/spark        # spin up + emit state
#   make spark-regtest-teardown WS=~/audits/spark        # stop bitcoind + clean pidfile
#   bash tools/spark-regtest-harness.sh --check          # validate prerequisites (no daemon)
#   bash tools/spark-regtest-harness.sh --help
#
# OUTPUT
# ------
# On success, writes <WS>/.auditooor/regtest_state.json with:
#   { "pid": <bitcoind-pid>, "rpc_url": "http://127.0.0.1:18443",
#     "rpc_user": "regtestaudit", "rpc_password": "regtestauditpassword",
#     "wallet": "harness_wallet", "height": 101, "funded_address": "<bech32>",
#     "started_at": "<iso8601>", "data_dir": "<WS>/.auditooor/regtest_data" }
#
# IDEMPOTENCY
# -----------
# If a pidfile already exists and the pid is alive + on regtest, this script
# skips spinup and emits the existing state JSON.

set -euo pipefail

##############################################################################
# Defaults / env
##############################################################################
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RPC_HOST="${BITCOIN_RPC_HOST:-127.0.0.1}"
RPC_PORT="${BITCOIN_RPC_PORT:-18443}"
RPC_USER="${BITCOIN_RPC_USER:-regtestaudit}"
RPC_PASS="${BITCOIN_RPC_PASSWORD:-regtestauditpassword}"
RPC_URL="http://${RPC_HOST}:${RPC_PORT}"

WALLET_NAME="harness_wallet"
MINE_BLOCKS=101   # enough for coinbase maturity

##############################################################################
# Arg parsing
##############################################################################
MODE="spinup"   # spinup | teardown | check
WS=""

usage() {
    grep '^#' "$0" | grep -v '#!/' | sed 's/^# \{0,2\}//'
    exit 0
}

for arg in "$@"; do
    case "$arg" in
        --help|-h)      usage ;;
        --check)        MODE="check" ;;
        --teardown)     MODE="teardown" ;;
        --ws=*)         WS="${arg#--ws=}" ;;
        WS=*)           WS="${arg#WS=}" ;;
        *)              ;;
    esac
done

# Also accept WS from environment (Makefile passes it via env var or positional).
WS="${WS:-${WS_ENV:-}}"

# Expand ~ manually so it works in all invocation contexts.
if [[ "$WS" == ~* ]]; then
    WS="${HOME}${WS:1}"
fi

##############################################################################
# Helpers
##############################################################################
log()  { echo "[spark-regtest] $*" >&2; }
pass() { echo "[PASS] $*"; }
fail() { echo "[FAIL] $*" >&2; exit 1; }

rpc() {
    # Minimal JSON-RPC call; returns raw result body or errors.
    local method="$1"; shift
    local params="${1:-[]}"
    curl -s --user "${RPC_USER}:${RPC_PASS}" \
         --data-binary "{\"jsonrpc\":\"1.0\",\"id\":\"harness\",\"method\":\"${method}\",\"params\":${params}}" \
         -H 'content-type: text/plain;' \
         "${RPC_URL}"
}

rpc_wallet() {
    local method="$1"; shift
    local params="${1:-[]}"
    curl -s --user "${RPC_USER}:${RPC_PASS}" \
         --data-binary "{\"jsonrpc\":\"1.0\",\"id\":\"harness\",\"method\":\"${method}\",\"params\":${params}}" \
         -H 'content-type: text/plain;' \
         "${RPC_URL}/wallet/${WALLET_NAME}"
}

rpc_result() {
    # Call rpc and return only the .result field (via python3 json module).
    local raw
    raw="$(rpc "$@")"
    echo "$raw" | python3 -c "import sys,json; d=json.load(sys.stdin); sys.exit(1) if d.get('error') else print(json.dumps(d['result']))"
}

rpc_wallet_result() {
    local raw
    raw="$(rpc_wallet "$@")"
    echo "$raw" | python3 -c "import sys,json; d=json.load(sys.stdin); sys.exit(1) if d.get('error') else print(json.dumps(d['result']))"
}

bitcoind_running() {
    # Return 0 if bitcoind is reachable at RPC_URL on regtest.
    local out chain
    out="$(rpc getblockchaininfo 2>/dev/null)" || return 1
    chain="$(echo "$out" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('result',{}).get('chain',''))" 2>/dev/null)"
    [[ "$chain" == "regtest" ]]
}

##############################################################################
# Prerequisite check (--check mode — no daemon spawned)
##############################################################################
check_prereqs() {
    local ok=0

    log "Checking prerequisites (no daemon launched)..."

    # bitcoind
    if command -v bitcoind &>/dev/null; then
        pass "bitcoind found: $(bitcoind -version 2>&1 | head -1)"
    else
        echo "[MISSING] bitcoind not found in PATH — install Bitcoin Core 25+ (brew install bitcoin or apt-get install bitcoind)"
        ok=1
    fi

    # bitcoin-cli (optional, nice to have)
    if command -v bitcoin-cli &>/dev/null; then
        pass "bitcoin-cli found: $(bitcoin-cli -version 2>&1 | head -1)"
    else
        echo "[WARN] bitcoin-cli not found — not required but useful for manual inspection"
    fi

    # python3 (for JSON parsing)
    if command -v python3 &>/dev/null; then
        pass "python3 found: $(python3 --version)"
    else
        echo "[MISSING] python3 not found — required for state JSON emission"
        ok=1
    fi

    # curl
    if command -v curl &>/dev/null; then
        pass "curl found"
    else
        echo "[MISSING] curl not found — required for RPC calls"
        ok=1
    fi

    if [[ $ok -eq 0 ]]; then
        pass "All prerequisites satisfied. Run 'make spark-regtest-harness WS=<path>' to spin up."
    else
        fail "Missing prerequisites — see above"
    fi
}

##############################################################################
# Teardown
##############################################################################
teardown() {
    local pidfile state_dir

    if [[ -n "$WS" ]]; then
        state_dir="${WS}/.auditooor"
        pidfile="${state_dir}/regtest_bitcoind.pid"
    else
        state_dir="/tmp/spark-regtest"
        pidfile="${state_dir}/regtest_bitcoind.pid"
    fi

    if [[ ! -f "$pidfile" ]]; then
        log "No pidfile at ${pidfile} — nothing to tear down."
        exit 0
    fi

    local pid
    pid="$(cat "$pidfile")"
    log "Stopping bitcoind pid=${pid}..."
    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid"
        local i=0
        while kill -0 "$pid" 2>/dev/null && [[ $i -lt 15 ]]; do
            sleep 1; i=$((i+1))
        done
        if kill -0 "$pid" 2>/dev/null; then
            log "bitcoind still alive after 15s, sending SIGKILL..."
            kill -9 "$pid" || true
        fi
        pass "bitcoind (pid=${pid}) stopped."
    else
        log "pid=${pid} already dead."
    fi

    rm -f "$pidfile"
    log "Removed pidfile ${pidfile}."
    log "Data dir preserved at ${state_dir}/regtest_data (delete manually if desired)."
}

##############################################################################
# Spinup
##############################################################################
spinup() {
    # Require WS for state JSON output.
    if [[ -z "$WS" ]]; then
        fail "WS is required for spinup mode. Usage: make spark-regtest-harness WS=~/audits/spark"
    fi

    local state_dir="${WS}/.auditooor"
    local data_dir="${state_dir}/regtest_data"
    local pidfile="${state_dir}/regtest_bitcoind.pid"
    local state_json="${state_dir}/regtest_state.json"

    mkdir -p "$state_dir" "$data_dir"

    ##########################################################################
    # Idempotency check: is bitcoind already running on this regtest instance?
    ##########################################################################
    if [[ -f "$pidfile" ]]; then
        local existing_pid
        existing_pid="$(cat "$pidfile")"
        if kill -0 "$existing_pid" 2>/dev/null && bitcoind_running; then
            log "bitcoind already running (pid=${existing_pid}) on regtest — skipping spinup."
            local height
            height="$(rpc_result getblockchaininfo '[]' | python3 -c "import sys,json; print(json.load(sys.stdin)['blocks'])")"
            log "Current regtest height: ${height}"
            pass "Idempotent skip — existing regtest instance reused."
            # Emit state JSON (refresh height).
            emit_state "$existing_pid" "$data_dir" "$state_json" "$height"
            return 0
        else
            log "Stale pidfile found (pid=${existing_pid} not responding); removing and respawning..."
            rm -f "$pidfile"
        fi
    fi

    ##########################################################################
    # Check if someone else's bitcoind is on the port.
    ##########################################################################
    if bitcoind_running; then
        fail "A bitcoind is already reachable at ${RPC_URL} but no pidfile found. \
Stop that instance first or set BITCOIN_RPC_PORT to a different port."
    fi

    ##########################################################################
    # Write regtest.conf.
    ##########################################################################
    local conf="${data_dir}/bitcoin.conf"
    cat > "$conf" <<EOF
regtest=1
server=1
daemon=1
fallbackfee=0.0001
txindex=1
rpcuser=${RPC_USER}
rpcpassword=${RPC_PASS}
rpcbind=${RPC_HOST}
rpcport=${RPC_PORT}
# listen=0 (regtest doesn't need P2P)
listen=0
EOF
    log "Wrote ${conf}"

    ##########################################################################
    # Spawn bitcoind.
    ##########################################################################
    log "Spawning bitcoind in regtest mode (data_dir=${data_dir})..."
    bitcoind -datadir="$data_dir" -conf="$conf" -pid="${pidfile}.tmp" 2>&1 &
    local spawn_pid=$!

    # Wait up to 15s for RPC to become responsive.
    local i=0
    log "Waiting for bitcoind RPC to become ready..."
    while ! bitcoind_running && [[ $i -lt 15 ]]; do
        sleep 1; i=$((i+1))
    done
    if ! bitcoind_running; then
        fail "bitcoind did not become ready within 15s (spawn_pid=${spawn_pid}). Check ${data_dir}/regtest/debug.log"
    fi

    # Capture pid (may differ from spawn_pid if bitcoind forked).
    local pid
    if [[ -f "${pidfile}.tmp" ]]; then
        pid="$(cat "${pidfile}.tmp")"
        mv "${pidfile}.tmp" "$pidfile"
    else
        # Fallback: find bitcoind process using lsof on the RPC port.
        pid="$(lsof -ti tcp:${RPC_PORT} 2>/dev/null | head -1 || echo "$spawn_pid")"
        echo "$pid" > "$pidfile"
    fi
    pass "bitcoind running (pid=${pid}) on regtest."

    ##########################################################################
    # Create wallet + mine 101 blocks.
    ##########################################################################
    log "Creating descriptor wallet '${WALLET_NAME}'..."
    # createwallet args: name, disable_private_keys, blank, passphrase, avoid_reuse, descriptors, load_on_startup
    rpc createwallet "[\"${WALLET_NAME}\",false,false,\"\",false,true,true]" >/dev/null 2>&1 || \
        rpc_result loadwallet "[\"${WALLET_NAME}\"]" >/dev/null

    log "Generating funded address..."
    local funded_addr
    funded_addr="$(rpc_wallet_result getnewaddress '["harness_funded","bech32"]' | tr -d '"')"
    pass "Funded address: ${funded_addr}"

    log "Mining ${MINE_BLOCKS} blocks to mature coinbase (this may take a moment)..."
    rpc_wallet_result generatetoaddress "[${MINE_BLOCKS},\"${funded_addr}\"]" >/dev/null
    pass "Mined ${MINE_BLOCKS} blocks — coinbase now spendable."

    local height
    height="$(rpc_result getblockchaininfo '[]' | python3 -c "import sys,json; print(json.load(sys.stdin)['blocks'])")"
    pass "Regtest height: ${height}"

    ##########################################################################
    # Emit state JSON.
    ##########################################################################
    emit_state "$pid" "$data_dir" "$state_json" "$height" "$funded_addr"
    pass "Harness ready. State at ${state_json}"
}

emit_state() {
    local pid="$1" data_dir="$2" state_json="$3" height="$4"
    local funded_addr="${5:-}"
    local now
    now="$(python3 -c "import datetime; print(datetime.datetime.utcnow().isoformat()+'Z')")"
    python3 - <<PYEOF
import json, sys
state = {
    "pid": ${pid},
    "rpc_url": "${RPC_URL}",
    "rpc_user": "${RPC_USER}",
    "rpc_password": "${RPC_PASS}",
    "wallet": "${WALLET_NAME}",
    "height": ${height},
    "funded_address": "${funded_addr}",
    "started_at": "${now}",
    "data_dir": "${data_dir}"
}
with open("${state_json}", "w") as f:
    json.dump(state, f, indent=2)
print(json.dumps(state, indent=2))
PYEOF
}

##############################################################################
# Dispatch
##############################################################################
case "$MODE" in
    check)    check_prereqs ;;
    teardown) teardown ;;
    spinup)   spinup ;;
esac

#!/usr/bin/env bash
# LEAD 1 v8 unified end-to-end opposed regtest runner.
# Severity: High
#
# Property: attacker (sender) withholds tx-real and supplies an unrelated txid
# via req.ExitTxid. Demonstrates that the chain watcher fires on the unrelated
# txid and reaches tweakKeysForCoopExit in production code.
#
# Role model:
#   attacker = sender; withholds tx-real
#   victim   = receiver; loses off-chain consideration

set -euo pipefail
WALLET="lead1_v8"
# --- Role separation: distinct addresses per actor ---
MINER_ADDR="$(bitcoin-cli -regtest getnewaddress miner bech32)"
LEAF_ADDR="$(bitcoin-cli -regtest getnewaddress leaf bech32)"
REFUND_ADDR="$(bitcoin-cli -regtest getnewaddress attacker_refund bech32)"
RECEIVER_ADDR="$(bitcoin-cli -regtest getnewaddress receiver_redemption bech32)"
UNRELATED_ADDR="$(bitcoin-cli -regtest getnewaddress unrelated bech32)"

# --- Withheld-artifact assertion loop ---
# Assert NO tx in the chain-watcher confirmation window spends the leaf parent UTXO P.
for tip in ${CHAIN_TIPS//,/ }; do
    HEIGHT="${tip%%:*}"
    HASH="${tip##*:}"
    TXS="$(bitcoin-cli -regtest getblock "$HASH" 2 | jq -r '.tx[].txid')"
    for txid in $TXS; do
        SPENDS="$(bitcoin-cli -regtest decoderawtransaction "$(bitcoin-cli -regtest getrawtransaction "$txid")" \
            | jq -r --arg ltxid "$LEAF_TXID" --argjson lvout "$LEAF_VOUT" \
            '[.vin[]? | select(.txid == $ltxid and .vout == $lvout)] | length')"
        if [ "$SPENDS" != "0" ]; then
            echo "FAIL: a tx in window spends leaf parent UTXO" >&2
            exit 1
        fi
    done
done

# --- Attack-causality assertion ---
# Production code must reach SENDER_KEY_TWEAKED / tweakKeysForCoopExit.
go test -run TestLead1_V8_SenderWithholdsTxReal -count=1 ./so/chain/ -v

# transfer.Status -> SENDER_KEY_TWEAKED asserted inside the Go test.
echo "PASS: opposed-trace v8 harness complete."

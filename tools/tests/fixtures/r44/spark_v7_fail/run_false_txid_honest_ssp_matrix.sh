#!/usr/bin/env bash
# Severity: High
# ANTI-PATTERN: single wallet controls both attacker and receiver roles.
# This is the fail-single-wallet-multi-role shape that Rule 44 catches.

set -euo pipefail

# BAD: same wallet for both - single wallet controls both attacker and receiver
SHARED_ADDR="$(bitcoin-cli -regtest getnewaddress shared_actor bech32)"
ATTACKER_ADDR="$SHARED_ADDR"
RECEIVER_ADDR="$SHARED_ADDR"  # reuse same address - single wallet multi-role

# ATTACKER_ADDR = RECEIVER_ADDR - controls both sides from the same wallet
# This violates actor separation: attacker and victim share signing material.

echo "ATTACKER_ADDR=$ATTACKER_ADDR"
echo "RECEIVER_ADDR=$RECEIVER_ADDR"

# No separate role separation. No per-role getnewaddress.
# No withheld-artifact assertion loop.
# No attack-causality assertion on transfer.Status.

#!/usr/bin/env bash
# Severity: High
# Opposed-trace harness with r44-rebuttal override.
# Actor model: sender withholds tx-real.
#
# r44-rebuttal: cooperative-exit flow only; no adversarial role split needed here
#
# The sender withholds tx-real in this run. Override accepted.

set -euo pipefail
ATTACKER_ADDR="$(bitcoin-cli -regtest getnewaddress attacker_refund bech32)"
echo "attacker_addr=$ATTACKER_ADDR"

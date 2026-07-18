#!/usr/bin/env bash
# Severity: High
# This is a cooperative case: both parties cooperate in this baseline harness.
# No attacker role; this is a cooperative scenario for control purposes.
# Rule 44 PASSES this with pass-cooperative-case-labeled.

set -euo pipefail

HONEST_ADDR="$(bitcoin-cli -regtest getnewaddress honest_party bech32)"
echo "honest_addr=$HONEST_ADDR"
echo "Both parties cooperate in this run. cooperative-case."

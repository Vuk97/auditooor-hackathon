#!/usr/bin/env bash
# bytecode-hash.sh — fetch and hash deployed runtime bytecode for regression detection
#
# Usage:
#   ./tools/bytecode-hash.sh <rpc-url> <address> [address2 ...]
#
# For each address, prints: address | code_len | keccak256(code)
#
# Use this to detect when a deployed contract differs from its source-compiled
# bytecode (e.g., a compromised deployment, wrong commit, post-audit tamper).

set -euo pipefail

if [ $# -lt 2 ]; then
    echo "Usage: $0 <rpc-url> <address> [address2 ...]"
    echo "Example: $0 https://polygon.drpc.org 0xE111180000d2663C0091e4f400237545B87B996B"
    exit 1
fi

RPC="$1"
shift

if ! command -v cast >/dev/null 2>&1; then
    echo "Error: cast not found. Install Foundry first."
    echo "  curl -L https://foundry.paradigm.xyz | bash && foundryup"
    exit 1
fi

printf "%-44s  %-10s  %s\n" "Address" "Code bytes" "keccak256(runtime code)"
printf "%-44s  %-10s  %s\n" "--------" "----------" "-----------------------"

for addr in "$@"; do
    code=$(cast code "$addr" --rpc-url "$RPC" 2>/dev/null || echo "0x")

    if [ "$code" = "0x" ] || [ -z "$code" ]; then
        printf "%-44s  %-10s  %s\n" "$addr" "0" "(no code)"
        continue
    fi

    # cast keccak hashes the raw bytes (minus 0x prefix)
    hash=$(cast keccak "$code")
    len=$(echo -n "$code" | wc -c | tr -d ' ')
    # -2 for the 0x prefix, /2 for hex-to-bytes
    byte_len=$(((len - 2) / 2))

    printf "%-44s  %-10s  %s\n" "$addr" "$byte_len" "$hash"
done

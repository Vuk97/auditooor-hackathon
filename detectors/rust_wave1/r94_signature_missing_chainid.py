"""
r94_signature_missing_chainid.py

Flags fns that build / verify a signed digest without binding the
network/chain identity (`env.ledger().network_id()` on Soroban, or a
chain_id / network_passphrase field inside the signed payload).  Same
signed blob can then be replayed on a sibling network (testnet -> mainnet,
fork, parallel deployment).

Maps to Solidity:
  - signature-missing-chainid-enables-cross-chain-replay
  - chainsec-spark-savings-intent-signature-replay-crosschain
  - r74-auth-cross-contract-signature-replay
  - halborn-crosschain-bridge-message-not-chainscoped

Heuristic:
  1. Body calls a sig-verify primitive (ed25519_verify / secp256k1_recover
     / .verify_sig).
  2. Body builds the digest from a `Bytes`/`BytesN`/`Vec` payload and does
     NOT reference any chain/network identifier:
     `network_id`, `chain_id`, `network_passphrase`, `CHAIN_ID`,
     `ledger().network_id()`.
  3. Skip `verify_*` helper fns.
"""

from __future__ import annotations

import re

from _util import (
    function_items, fn_body, fn_name, text_of, walk_no_nested_fn,
    line_col, snippet_of, in_test_cfg,
)


_SIG_VERIFY_PATTERNS = (
    r"ed25519_verify",
    r"secp256k1_recover",
    r"secp256r1_verify",
    r"\.verify_sig\b",
    r"\.verify_signature\b",
)

_CHAIN_TOKENS = (
    "network_id", "network_passphrase", "chain_id", "CHAIN_ID",
    "chainid", "NETWORK_ID", "netuid", "net_id",
)


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        name = fn_name(fn, source)
        if name.startswith("verify_") or name.startswith("_verify"):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_text = text_of(body, source)

        if not any(re.search(p, body_text) for p in _SIG_VERIFY_PATTERNS):
            continue

        # Require downstream side-effect (real consumer, not a helper).
        if "storage()" not in body_text and ".set(" not in body_text \
                and ".invoke_contract" not in body_text \
                and ".transfer(" not in body_text \
                and ".mint(" not in body_text:
            continue

        if any(tok in body_text for tok in _CHAIN_TOKENS):
            continue

        verify_node = None
        for n in walk_no_nested_fn(body):
            if n.type != "call_expression":
                continue
            t = text_of(n, source)
            if any(re.search(p, t) for p in _SIG_VERIFY_PATTERNS):
                verify_node = n
                break
        if verify_node is None:
            continue

        line, col = line_col(verify_node)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(verify_node, source),
            "message": (
                f"fn `{name}` verifies a signature without binding the "
                f"digest to any network/chain identifier "
                f"(`network_id` / `chain_id` / `ledger().network_id()`) — "
                f"signature forged for one network can be replayed on a "
                f"sibling deployment."
            ),
        })
    return hits

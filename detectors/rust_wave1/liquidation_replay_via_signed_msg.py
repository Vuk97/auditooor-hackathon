"""
liquidation_replay_via_signed_msg.py

Flags fns that verify an off-chain signed payload (Ed25519 / secp256k1) and
consume it for a privileged action (liquidation, order fill, permit) but
do not record the signature as used / do not include a nonce.

Heuristic:
  1. Body calls `env.crypto().ed25519_verify(...)` OR `.secp256k1_recover(...)`
     OR `.sha256(...).verify(...)`.
  2. Body does NOT mark the digest / nonce as consumed by writing to
     a storage key whose name contains `nonce`, `used_sig`, `seen`,
     `consumed`, `fills`, or incrementing a counter.

False-positive filter: skip fns whose names start with `verify_` —
pure-verification helpers that return a bool for a caller to consume.
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
)

_REPLAY_GUARD_HINTS = (
    "nonce", "used_sig", "seen", "consumed", "fills",
    "signature_used", "replay", "order_filled",
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

        # Must call a sig-verify primitive
        if not any(re.search(p, body_text) for p in _SIG_VERIFY_PATTERNS):
            continue
        # Must not mention any replay-guard key
        if any(h in body_text for h in _REPLAY_GUARD_HINTS):
            continue
        # Additional FP filter: pure helper with no storage write
        if "storage()" not in body_text and ".set(" not in body_text \
                and ".invoke_contract" not in body_text \
                and ".transfer(" not in body_text:
            continue

        # Locate the verify call node for line info
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
                f"fn `{name}` verifies a signature and acts on it without "
                f"any nonce / replay guard in the body — signed payload can "
                f"be replayed."
            ),
        })
    return hits

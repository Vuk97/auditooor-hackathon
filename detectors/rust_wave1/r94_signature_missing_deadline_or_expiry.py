"""
r94_signature_missing_deadline_or_expiry.py

Flags fns that verify an off-chain signed payload (Ed25519 / secp256k1 /
custom `.verify_sig`) without comparing against a deadline / expiry /
valid_until ledger timestamp — signed quote or intent can be replayed
indefinitely once the signer forgets about it.

Heuristic:
  1. Body calls a signature-verify primitive (same set as
     `liquidation_replay_via_signed_msg.py`).
  2. Body does NOT contain any deadline/expiry/valid_until token AND
     does NOT compare `env.ledger().timestamp()` (or a `now`/`block.ts`
     snapshot) against a stored timestamp.
  3. Skip `verify_*` helper fns — they're pure helpers.

Maps to the Solidity `deadline-hardcoded-type-max` / `hexens-rfq-taker-
signature-no-deadline-reused-quote` class ported to Soroban.
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

_DEADLINE_TOKENS = (
    "deadline", "expiry", "valid_until", "expires_at", "not_after",
    "max_timestamp", "expires", "valid_to", "valid_till",
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
        # Skip pure helpers: no downstream storage mutation / transfer /
        # invoke means it's probably a verification pass-through.
        if "storage()" not in body_text and ".set(" not in body_text \
                and ".invoke_contract" not in body_text \
                and ".transfer(" not in body_text \
                and ".mint(" not in body_text:
            continue

        lower = body_text.lower()
        if any(t in lower for t in _DEADLINE_TOKENS):
            continue
        # Also allow if a stored ts is compared against ledger().timestamp()
        # with a guard (panic if expired).
        if re.search(
            r"ledger\s*\(\s*\)\s*\.\s*timestamp\s*\(\s*\)\s*[<>]", body_text
        ):
            continue

        # Locate the verify call node
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
                f"fn `{name}` verifies a signature and consumes it for a "
                f"privileged op without any deadline / expiry / "
                f"valid_until comparison against `env.ledger().timestamp()` "
                f"— signed payload is valid forever (replay window "
                f"unbounded)."
            ),
        })
    return hits

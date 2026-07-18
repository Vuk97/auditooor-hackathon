"""
r94_merkle_claim_no_claimed_flag.py

Flags `claim` / `claim_airdrop` / `claim_rewards` / `redeem_merkle` fns
that verify a merkle proof and transfer / mint tokens without persisting
a per-index or per-leaf "claimed" flag.  Same proof can then be replayed
to drain the pot.

Maps to Solidity:
  - balancer-merkle-orchard-batched-duplicate-claim
  - duplicate-entries-in-batch-claim
  - can-merkle-drop-no-per-index-flag
  - extraneous-approval-in-withdrawal-double-claim

Heuristic:
  1. Body calls something matching `verify_proof` / `merkle_verify` /
     `verify_merkle` / `.compute_root(` / `proof_verify`.
  2. Body then performs a payout: `.transfer(`, `.mint(`, `.send(`,
     `.invoke_contract`.
  3. Body does NOT write a claimed flag: key name / identifier contains
     `claimed`, `Claimed`, `CLAIMED`, `claims`, `used_leaf`, `leaf_used`,
     `bitmap_set`, `set_bit`, or a call to `.set_bit(`.
"""

from __future__ import annotations

import re

from _util import (
    function_items, fn_body, fn_name, text_of, walk_no_nested_fn,
    line_col, snippet_of, in_test_cfg,
)


_MERKLE_VERIFY_RE = re.compile(
    r"verify_proof|merkle_verify|verify_merkle|\.compute_root\s*\(|"
    r"proof_verify|verify_merkle_proof|merkle::verify"
)

_PAYOUT_RE = re.compile(
    r"\.transfer\s*\(|\.mint\s*\(|\.send\s*\(|"
    r"\.invoke_contract\s*\(|\.safe_transfer\s*\("
)

_CLAIMED_TOKENS = (
    "claimed", "Claimed", "CLAIMED", "claims", "Claims",
    "used_leaf", "leaf_used", "UsedLeaf",
    "bitmap_set", "set_bit", ".set_bit(", "claim_bitmap",
    "consumed_leaf", "consumed_claim",
)


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        name = fn_name(fn, source)
        body = fn_body(fn)
        if body is None:
            continue
        body_text = text_of(body, source)

        if not _MERKLE_VERIFY_RE.search(body_text):
            continue
        if not _PAYOUT_RE.search(body_text):
            continue
        if any(tok in body_text for tok in _CLAIMED_TOKENS):
            continue

        # Locate the verify call node
        verify_node = None
        for n in walk_no_nested_fn(body):
            if n.type != "call_expression":
                continue
            if _MERKLE_VERIFY_RE.search(text_of(n, source)):
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
                f"fn `{name}` verifies a merkle proof and pays out tokens "
                f"without writing a per-index / per-leaf `claimed` flag "
                f"— same proof can be replayed to drain the distributor."
            ),
        })
    return hits

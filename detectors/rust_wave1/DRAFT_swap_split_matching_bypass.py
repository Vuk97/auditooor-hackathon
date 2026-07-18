"""
DRAFT_swap_split_matching_bypass.py

# DRAFT: auto-generated sibling for swap-split-matching-bypass (source side: solidity).
# Review required before enabling. Do NOT add to test_detectors.sh yet.

BUG_CLASS: swap-split-matching-bypass
description: Small-swap splitting yields better price than intended bulk matching (CLOB/orderbook algo flaw — EVM-common)

Auto-translated from: reference/patterns.dsl/cross-market-price-sum-gte-one-leaves-free-taker.yaml

This is a REVIEWER PROMPT — translation is best-effort from the Solidity
DSL regex/precondition shape into a tree-sitter-rust heuristic. Human must:
  1. Confirm the bug-class actually manifests on the Rust side (Soroban /
     Solana / Move / Sway / FunC / TON / CosmWasm). If not, delete this file
     and leave the class `solidity_only`.
  2. Replace the naive regex scan below with AST-level predicates matching
     the actual Rust shape of the bug (see e.g. delegatecall_to_user_address.py
     which ports EVM delegatecall → Soroban SEP-41 transfer-from spoof).
  3. Add fixtures: test_fixtures/DRAFT_swap_split_matching_bypass_positive.rs
     and _negative.rs, then register in test_detectors.sh.
"""
from __future__ import annotations

import re

from _util import (
    body_text_nocomment,
    fn_body,
    fn_name,
    functions_in_contractimpl,
    is_pub,
    line_col,
    snippet_of,
)


_FN_NAME_RE = re.compile(r"(?i)(match|fill|swap|quote|execute|take)")
_PRICE_SUM_RE = re.compile(
    r"(?i)(price_sum|priceSum|sum_of_prices|sumOfPrices)\s*(>=|==)\s*(ONE|1e18)"
)
_REMAINDER_RE = re.compile(
    r"(?is)(if\s+notional_so_far\s*>=\s*fill_amount\s*\{\s*0\s*\}\s*else\s*\{\s*"
    r"fill_amount\s*-\s*notional_so_far\s*\}|fill_amount\s*-\s*notional_so_far)"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        if not _PRICE_SUM_RE.search(body_nc):
            continue
        if not _REMAINDER_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "low",  # TODO: calibrate after fixtures
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source),
            "message": (
                f"pub fn `{name}` appears to gate fills on a raw outcome "
                "price-sum equality/threshold and then computes leftover "
                "notional directly from `fill_amount - notional_so_far`. "
                "That shape is susceptible to split-order matching bypasses."
            ),
        })
    return hits


# --- Source-side excerpt (reference only) ------------------------------------
# # Auto-migrated by tools/dsl-migration-helper.py 2026-04-19 | pattern: cross-market-price-sum-gte-one-leaves-free-taker | source: auditooor-R76-cyfrin-myriad-clob-H2 | severity: HIGH | confidence: MEDIUM |  | # Audit: Cyfrin Myriad CLOB · H-2 | # URL: same as above | # | # Bug class: In a NegRisk / multi-outcome CLOB

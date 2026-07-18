"""
r94_loop_asymmetric_liquidity_flat_oracle.py

Flags DEX/pool fns that price a swap purely off an oracle/TWAP whenever
one reserve side is zero/empty — bypassing the intended spread/slippage
that a real AMM curve imposes.

Source: Solodit #63651 (Sherlock / Dango DEX).
Class: asymmetric-liquidity-flat-oracle.
"""

from __future__ import annotations

import re

from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)


_FN_NAME_RE = re.compile(
    r"(?i)(swap|ask_|bid_|quote_|get_price|price_for|compute_output)"
)

_ONE_SIDED_BRANCH_RE = re.compile(
    r"(reserve[0-9]?_?(a|b|x|y|in|out)|balance[0-9]?)\s*==\s*0|"
    r"is_empty\s*\(\)|len\s*\(\)\s*==\s*0|"
    r"liquidity\s*==\s*0"
)

_ORACLE_PRICE_RE = re.compile(
    r"oracle_price|get_oracle|\.oracle\s*\(|get_price_from_oracle|"
    r"twap|pyth|chainlink|reflector|price_feed"
)

_SIZE_SCALING_RE = re.compile(
    r"amount\s*\*\s*(slippage|spread|fee_bps|scale_by_size|impact)|"
    r"price_impact\s*\(|dynamic_spread\s*\(|apply_slippage"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    root = tree.root_node
    for fn, _impl in functions_in_contractimpl(root, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)

        if not _ONE_SIDED_BRANCH_RE.search(body_nc):
            continue
        if not _ORACLE_PRICE_RE.search(body_nc):
            continue
        if _SIZE_SCALING_RE.search(body_nc):
            continue

        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` hits an 'empty reserve' branch that "
                f"prices the swap at oracle/TWAP price without any size-"
                f"based slippage/spread scaling. Attacker trades large "
                f"size against an asymmetric pool at flat oracle price → "
                f"risk-free arb / oracle-level drain. See Solodit #63651 "
                f"(Dango DEX)."
            ),
        })
    return hits

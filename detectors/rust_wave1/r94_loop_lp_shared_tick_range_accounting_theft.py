"""
r94_loop_lp_shared_tick_range_accounting_theft.py

Flags burn/withdraw fns that call `pool.burn(tick_lower, tick_upper,
liquidity)` using caller-supplied tick_lower/tick_upper WITHOUT
looking up the caller's own tracked liquidity in the pair — two
pairs sharing a tick range can steal from each other.

Source: Solodit #34885 (Predy shared tick range).
Class: lp-shared-tick-range-accounting-theft (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(reallocate|rebalance|burn_range|withdraw_liquidity|flash_burn|unwind_position)")
_POOL_BURN_RE = re.compile(
    r"(pool|uniswap|v3_pool|nft_position_manager)\s*\.\s*burn\s*\(\s*"
    r"(tick_lower|tickLower|tl)\s*,\s*(tick_upper|tickUpper|tu)"
)
_OWNER_KEY_RE = re.compile(
    r"position_key\s*\(\s*\w*(owner|pair|self|this)|"
    r"keccak\s*\(\s*abi::encode\s*\(\s*(owner|pair|address\(this\))|"
    r"self\.pair_liquidity|pair_id\s*,\s*tick_lower|"
    r"pair_liquidity_at\s*\("
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
        if not _POOL_BURN_RE.search(body_nc):
            continue
        if _OWNER_KEY_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` burns LP liquidity at a tick range "
                f"without keying on pair/owner id — two pairs sharing "
                f"range commingle and one can burn the other's "
                f"liquidity (lp-shared-tick-range-accounting-theft). "
                f"See Solodit #34885 (Predy)."
            ),
        })
    return hits

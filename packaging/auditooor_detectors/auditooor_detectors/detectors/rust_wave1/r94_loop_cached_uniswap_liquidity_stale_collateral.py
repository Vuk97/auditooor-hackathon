"""
r94_loop_cached_uniswap_liquidity_stale_collateral.py

Flags collateral-valuation fns that read a CACHED `position_liquidity`
/ `stored_liquidity` value instead of calling the pool/position
manager LIVE — borrower can decrease v3 liquidity after deposit,
keeping inflated collateral value.

Source: Solodit #30447 (Sherlock Arcadia AccountV1).
Class: cached-uniswap-liquidity-stale-collateral (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(
    r"(?i)(value_of_position|value_v3|collateral_value|get_collateral|"
    r"account_value|check_health|get_position_value)"
)
_CACHED_READ_RE = re.compile(
    r"(position_liquidity|stored_liquidity|cached_liquidity|liquidity_at_deposit|"
    r"self\.position_liquidity|accounts?\[\w+\]\.liquidity)"
)
_LIVE_READ_RE = re.compile(
    r"position_manager\s*\.\s*positions\s*\(|"
    r"nft_position_manager\s*\.\s*positions\s*\(|"
    r"pool\s*\.\s*positions\s*\(|"
    r"get_position_info\s*\(|"
    r"\.position\s*\(\s*\w+\s*\)\s*\.\s*liquidity"
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
        if not _CACHED_READ_RE.search(body_nc):
            continue
        if _LIVE_READ_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` reads a cached position_liquidity "
                f"value for collateral valuation — borrower can "
                f"decrease v3 liquidity after deposit, collateral "
                f"value becomes fake (cached-uniswap-liquidity-stale-"
                f"collateral). See Solodit #30447 (Arcadia)."
            ),
        })
    return hits

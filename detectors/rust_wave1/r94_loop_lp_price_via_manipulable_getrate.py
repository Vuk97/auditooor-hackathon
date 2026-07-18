"""
r94_loop_lp_price_via_manipulable_getrate.py

Flags LP oracle get_price fns that read `pool.get_rate()` /
`pool.virtual_price()` / `pool.price()` as a valuation component
without pairing it with a reentrancy guard check or safe-read helper.

Source: Solodit #24316 (Sherlock Blueberry Stable BPT).
Class: lp-price-via-manipulable-getrate (both).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)

_FN_NAME_RE = re.compile(r"(?i)(get_price|price_of_lp|compute_lp_value|valueOfBpt|value_of_bpt)")
_GET_RATE_RE = re.compile(
    r"\.get_rate\s*\(|\.virtual_price\s*\(|\.getRate\s*\(|\.virtualPrice\s*\(|"
    r"\.rate\s*\(\s*\)"
)
_SAFE_READ_RE = re.compile(
    r"reentrancy_guard|readonly_reentrancy|_checkNotInVaultContext|"
    r"BalancerVault\.getPoolTokens[\s\S]*?require|get_rate_safe|safe_virtual_price"
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
        if not _GET_RATE_RE.search(body_nc):
            continue
        if _SAFE_READ_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` prices an LP via pool.get_rate() / "
                f"virtual_price() with no reentrancy-guard / safe-read "
                f"check. Flash-borrow to skew pool state → LP "
                f"misvaluation. See Solodit #24316 (Blueberry)."
            ),
        })
    return hits

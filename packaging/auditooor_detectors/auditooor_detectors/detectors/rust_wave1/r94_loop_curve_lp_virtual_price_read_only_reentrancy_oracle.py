"""
r94_loop_curve_lp_virtual_price_read_only_reentrancy_oracle.py

Flags LP-token oracle fns that read Curve-style
`get_virtual_price()` (or `virtualPrice()`) without first
triggering a no-op `remove_liquidity` / external-reentrancy
guard. Read-only reentrancy during an add/remove_liquidity on
the underlying pool returns an inflated virtual_price,
causing unwarranted liquidations / bad collateral valuation.

Source: Solodit #5643 (Sherlock Sentiment wstETH-ETH oracle).
Class: curve-lp-virtual-price-read-only-reentrancy-oracle (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(
    r"(?i)(get_price|price|latest_price|lp_price|"
    r"get_lp_price|get_virtual_price_price|"
    r"compute_lp_value|fetch_lp_price)"
)
_VP_CALL_RE = re.compile(
    r"(?i)(get_virtual_price|getVirtualPrice|"
    r"virtual_price\s*\(\s*\)|virtualPrice\s*\(\s*\))"
)
# Safe: read-only reentrancy mitigation.
_GUARD_RE = re.compile(
    r"(?i)(remove_liquidity\s*\(\s*0\s*,|"
    r"removeLiquidity\s*\(\s*0\s*,|"
    r"claim_admin_fees|"
    r"reentrancy_check|"
    r"read_only_reentrancy_guard|readOnlyReentrancyGuard|"
    r"check_curve_pool_not_entered|"
    r"curve_pool_lock_state)"
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
        if not _VP_CALL_RE.search(body_nc):
            continue
        if _GUARD_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` reads Curve `get_virtual_price()` "
                f"without a read-only-reentrancy mitigation (e.g. "
                f"`remove_liquidity(0, 0)` probe, lock-state check) — "
                f"during an in-flight add/remove_liquidity the "
                f"value is inflated, causing unwarranted liquidations "
                f"(curve-lp-virtual-price-read-only-reentrancy-oracle). "
                f"See Solodit #5643 (Sherlock Sentiment wstETH-ETH)."
            ),
        })
    return hits

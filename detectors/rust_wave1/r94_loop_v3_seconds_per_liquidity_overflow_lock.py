"""
r94_loop_v3_seconds_per_liquidity_overflow_lock.py

Flags UniV3Staker unstake / claim_reward fns that read
`seconds_per_liquidity_inside` (u128 / u160) and use checked_sub —
with tiny liquidity + long elapsed time the value overflows u128
on the pool side; checked math on the staker side panics and the
position is locked.

Source: Solodit #26051 (C4 Maia DAO UniswapV3Staker).
Class: v3-seconds-per-liquidity-overflow-lock (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(unstake|claim_reward|collect_reward|withdraw_stake|end_incentive)")
_SECONDS_READ_RE = re.compile(
    r"seconds_per_liquidity_inside|secondsPerLiquidityInside|"
    r"seconds_per_liquidity_cumulative|secondsPerLiquidityCumulative"
)
_CHECKED_SUB_RE = re.compile(
    r"checked_sub\s*\(|\.saturating_sub|"
    r"(seconds_per_liquidity\w*)\s*-\s*(seconds_per_liquidity\w*|initial_seconds\w*)"
)
_UNCHECKED_RE = re.compile(
    r"\bunchecked\b|wrapping_sub|overflowing_sub|\.wrapping_sub"
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
        if not _SECONDS_READ_RE.search(body_nc):
            continue
        if _UNCHECKED_RE.search(body_nc):
            continue
        if not _CHECKED_SUB_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` subtracts seconds_per_liquidity "
                f"values with checked math — value overflows u160/u128 "
                f"under tiny-liquidity + long-time, position locked "
                f"(v3-seconds-per-liquidity-overflow-lock). See "
                f"Solodit #26051 (Maia UniswapV3Staker)."
            ),
        })
    return hits

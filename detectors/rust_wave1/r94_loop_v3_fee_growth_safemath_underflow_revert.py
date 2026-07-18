"""
r94_loop_v3_fee_growth_safemath_underflow_revert.py

Flags UniswapV3 position-value / fee-growth helpers that compute
`fee_growth_global - fee_growth_below - fee_growth_above` (or use
`checked_sub` / Solidity's Solidity 0.8 default checks) where the
math is EXPECTED to underflow-wrap — checked arithmetic panics
and the fn reverts instead of returning the correct value.

Source: Solodit #29697 (Particle Protocol).
Class: v3-fee-growth-safemath-underflow-revert (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(
    r"(?i)(fee_growth|total_fees|position_fees|compute_fees|fees_owed|calc_fees)"
)
_GLOBAL_MINUS_RE = re.compile(
    r"(fee_growth_global\w*|feeGrowthGlobal\w*)\s*[-]\s*(fee_growth_(below|above|inside)|feeGrowth(Below|Above|Inside))|"
    r"(fee_growth_inside|feeGrowthInside)\s*[-]\s*(fee_growth_last|feeGrowthLast)|"
    r"(fee_growth_global\w*|feeGrowthGlobal\w*)\s*\.\s*checked_sub\s*\(|"
    r"\.\s*checked_sub\s*\(\s*(fee_growth_(below|above|inside)|feeGrowth(Below|Above|Inside))"
)
_CHECKED_SUB_RE = re.compile(
    r"checked_sub\s*\(|\.saturating_sub\s*\(|overflow_sub\s*\("
)
_UNCHECKED_RE = re.compile(
    r"\bunchecked\b|overflowing_sub|wrapping_sub|\.wrapping_sub|"
    r"assembly\s*\{|unchecked\s*\{"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        if not _GLOBAL_MINUS_RE.search(body_nc):
            continue
        if _UNCHECKED_RE.search(body_nc):
            continue
        # if using checked_sub explicitly, the safeguard is itself the bug (will panic)
        # so don't skip on checked_sub - fire either way if no unchecked wrap.
        if _CHECKED_SUB_RE.search(body_nc):
            # definite positive — checked sub on intentional underflow
            line, col = line_col(fn)
            hits.append({
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:200],
                "message": (
                    f"fn `{name}` calls checked_sub on fee_growth "
                    f"fields that are designed to underflow-wrap — "
                    f"operation panics and reverts (v3-fee-growth-"
                    f"safemath-underflow-revert). See Solodit #29697 "
                    f"(Particle)."
                ),
            })
            continue
        # Solidity-style `-` without unchecked{} is also problematic
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"fn `{name}` subtracts fee_growth_{{below,above}} from "
                f"fee_growth_global without unchecked wrapping — "
                f"intentional underflow panics under safemath "
                f"(v3-fee-growth-safemath-underflow-revert). See "
                f"Solodit #29697 (Particle)."
            ),
        })
    return hits

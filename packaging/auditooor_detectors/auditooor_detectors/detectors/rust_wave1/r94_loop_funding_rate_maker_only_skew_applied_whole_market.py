"""
r94_loop_funding_rate_maker_only_skew_applied_whole_market.py

Flags funding-rate computation fns that derive the rate from a SINGLE
maker / oracle-maker's skew but apply the result across the WHOLE
market — attacker perturbs maker skew at low cost and collects
funding on every position.

Source: Solodit #32163 (Sherlock Perpetual).
Class: funding-rate-maker-only-skew-applied-whole-market (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(update_funding|compute_funding_rate|accrue_funding|calc_funding)")
_MAKER_SKEW_SOURCE_RE = re.compile(
    r"(oracle_maker|maker_pool|primary_maker|single_maker)\s*\.\s*(skew|imbalance|net_position)|"
    r"let\s+skew\s*=\s*(oracle_maker|maker_pool|primary_maker)\s*\.\s*"
)
_MARKET_WIDE_APPLY_RE = re.compile(
    r"(market_funding|global_funding|total_funding|all_positions_funding|"
    r"for\s+pos\s+in\s+positions|positions\.iter)"
)
_WHOLE_MARKET_SKEW_RE = re.compile(
    r"(global_skew|total_market_skew|aggregate_skew|net_market_skew|weighted_market_skew)"
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
        if not _MAKER_SKEW_SOURCE_RE.search(body_nc):
            continue
        if not _MARKET_WIDE_APPLY_RE.search(body_nc):
            continue
        if _WHOLE_MARKET_SKEW_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` derives funding rate from a single "
                f"maker's skew but applies it across the entire market "
                f"— attacker perturbs maker skew at low cost, collects "
                f"funding (funding-rate-maker-only-skew-applied-whole-"
                f"market). See Solodit #32163 (Perpetual)."
            ),
        })
    return hits

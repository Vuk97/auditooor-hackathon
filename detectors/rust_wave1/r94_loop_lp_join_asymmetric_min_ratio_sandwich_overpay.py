"""
r94_loop_lp_join_asymmetric_min_ratio_sandwich_overpay.py

Flags `on_join_pool` / `add_liquidity` fns that compute `amountLP`
as `min(token0In * supply / reserve0, token1In * supply / reserve1)`
without a pre-join price / oracle check — attacker sandwiches to
skew reserves so one side wildly overpays for the LP shares minted.

Source: Solodit #7113 (Spearbit Cron Finance CronV1Pool).
Class: lp-join-asymmetric-min-ratio-sandwich-overpay (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(on_join_pool|onJoinPool|add_liquidity|addLiquidity|"
    r"join_pool|joinPool|mint_lp|deposit_to_pool|lp_mint)"
)
_MIN_RATIO_RE = re.compile(
    fr"(?i)(min\s*\(\s*{IDENT}token0_in\s*\*\s*{IDENT}supply\s*\/\s*{IDENT}reserve0\s*,\s*{IDENT}token1_in\s*\*\s*{IDENT}supply\s*\/\s*{IDENT}reserve1|"
    fr"Math\.min\s*\(\s*{IDENT}token0In\s*\*\s*{IDENT}supply\s*\/\s*{IDENT}reserve0\s*,\s*{IDENT}token1In\s*\*\s*{IDENT}supply\s*\/\s*{IDENT}reserve1|"
    fr"amountLP\s*=\s*{IDENT}Math\.min\s*\(\s*{IDENT}_token0InU\w*\s*\.\s*mul\s*\(\s*{IDENT}supplyLP\s*\)|"
    fr"amount_lp\s*=\s*{IDENT}_token0_in\s*\.\s*mul\s*\(\s*{IDENT}supply_lp\s*\))"
)
_GUARD_RE = re.compile(
    fr"(?i)(min_amount_lp_out|minAmountLpOut|"
    fr"slippage_check|oracle_price_check|"
    fr"require\s*\(\s*{IDENT}amountLP\s*>=\s*{IDENT}min|"
    fr"pre_join_price|preJoinPrice|"
    fr"weighted_price_check|check_join_ratio)"
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
        if not _MIN_RATIO_RE.search(body_nc):
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
                f"pub fn `{name}` computes amountLP = min(tokenInA * "
                f"supply/reserveA, tokenInB * supply/reserveB) without "
                f"a pre-join price / min-out check — attacker "
                f"sandwiches to skew reserves so one side wildly "
                f"overpays "
                f"(lp-join-asymmetric-min-ratio-sandwich-overpay). "
                f"See Solodit #7113 (Spearbit Cron Finance)."
            ),
        })
    return hits

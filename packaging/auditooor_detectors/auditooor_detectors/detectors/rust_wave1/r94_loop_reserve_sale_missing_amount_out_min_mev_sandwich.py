"""
r94_loop_reserve_sale_missing_amount_out_min_mev_sandwich.py

Flags reserve / treasury / flash-swap-router fns that sell
protocol-owned assets via DEX without an explicit amountOutMin
parameter — sandwich MEV extracts value from protocol liquidity.

Source: Solodit #53125 (Cantina Cork FlashSwapRouter _sellDsReserve).
Class: reserve-sale-missing-amount-out-min-mev-sandwich (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(
    r"(?i)(_sell_ds_reserve|sellDsReserve|"
    r"sell_reserve|sellReserve|"
    r"liquidate_reserve|liquidateReserve|"
    r"sell_treasury|sellTreasury|"
    r"_sell_idle_funds|sellIdleFunds|"
    r"reserve_to_asset|reserveToAsset)"
)
_DEX_CALL_RE = re.compile(
    r"(?i)(uniswap\w*\s*\.\s*swap|"
    r"router\s*\.\s*swap|"
    r"pool\s*\.\s*swap|"
    r"\.\s*exact_input_single|exactInputSingle|"
    r"\.\s*swap_exact_tokens|swapExactTokens|"
    r"sold_amount\s*=)"
)
_MIN_OUT_RE = re.compile(
    r"(?i)(min_amount_out|minAmountOut|min_out|minOut|"
    r"amount_out_min|amountOutMin|amountOutMinimum|"
    r"sqrt_price_limit|sqrtPriceLimit|"
    fr"require\s*\(\s*{IDENT}received\s*>=\s*{IDENT}expected|"
    r"slippage_bps|slippageBps|tolerance_check|"
    r"oracle_floor_price)"
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
        if not _DEX_CALL_RE.search(body_nc):
            continue
        if _MIN_OUT_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` sells protocol reserve / treasury "
                f"assets via DEX with no amountOutMin / slippage "
                f"guard — sandwich MEV extracts value from protocol "
                f"liquidity "
                f"(reserve-sale-missing-amount-out-min-mev-sandwich). "
                f"See Solodit #53125 (Cantina Cork FlashSwapRouter)."
            ),
        })
    return hits

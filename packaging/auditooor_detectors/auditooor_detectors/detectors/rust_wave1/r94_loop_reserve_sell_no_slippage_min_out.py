"""
r94_loop_reserve_sell_no_slippage_min_out.py

Flags protocol-reserve sell fns (_sell_ds_reserve, sell_reserve,
liquidate_reserve) that swap reserve tokens to liquidity pool with
no amount_out_minimum — LP reserves sandwiched on every trigger.

Source: Solodit #53125 (Cantina Cork FlashSwapRouter).
Class: reserve-sell-no-slippage-min-out (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(
    r"(?i)(sell_reserve|sell_ds_reserve|liquidate_reserve|"
    r"auction_reserve|swap_reserve|flush_reserve)"
)
_SWAP_RE = re.compile(
    fr"(\.swap|\.exact_input|\.exact_output|router\.{IDENT}swap)\s*\("
)
_HAS_MIN_OUT_RE = re.compile(
    r"amount_out_minimum\s*:\s*[a-zA-Z_]\w*|"
    r"min_out\s*:\s*[a-zA-Z_]\w*|"
    r"amountOutMin(imum)?\s*:\s*[a-zA-Z_]\w*|"
    r"min_amount_out\s*[:=]\s*[a-zA-Z_]\w*"
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
        if not _SWAP_RE.search(body_nc):
            continue
        if _HAS_MIN_OUT_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"fn `{name}` sells protocol reserves via swap with no "
                f"amount_out_minimum — LP reserves sandwiched on every "
                f"trigger (reserve-sell-no-slippage-min-out). "
                f"See Solodit #53125 (Cork FlashSwapRouter)."
            ),
        })
    return hits

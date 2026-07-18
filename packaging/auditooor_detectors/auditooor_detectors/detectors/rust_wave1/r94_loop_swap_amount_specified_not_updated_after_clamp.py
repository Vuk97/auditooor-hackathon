"""
r94_loop_swap_amount_specified_not_updated_after_clamp.py

Flags swap fns that clamp `sqrt_price_next` / `price_limit_next`
to a bound but DON'T reduce `amount_specified` / `amount_remaining`
proportionally — user pays full amount for the clamped portion,
excess locked.

Source: Solodit #40243 (Cantina Marginal MarginalV1LBPool.swap).
Class: swap-amount-specified-not-updated-after-clamp (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(r"(?i)(swap|swap_step|swap_exact_in|swap_exact_out|compute_swap_step)")
_CLAMP_RE = re.compile(
    r"(sqrt_price_next|sqrtPriceNext|price_limit_next)\s*=\s*\w*(min|max|clamp|bound)|"
    fr"if\s+{IDENT}price\w*\s*(>|<)\s*\w*(bound|price_limit|priceLimit)[\s\S]{{0,120}}?(sqrt_price_next|sqrtPriceNext)\s*="
)
_UPDATE_AMOUNT_RE = re.compile(
    r"(amount_specified|amountSpecified|amount_remaining|amountRemaining)\s*(-=|=\s*\w+\s*-)"
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
        if not _CLAMP_RE.search(body_nc):
            continue
        if _UPDATE_AMOUNT_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` clamps sqrt_price_next / price_limit "
                f"but doesn't reduce amount_specified — user pays full "
                f"amount for clamped portion, excess locked (swap-"
                f"amount-specified-not-updated-after-clamp). See "
                f"Solodit #40243 (Marginal)."
            ),
        })
    return hits

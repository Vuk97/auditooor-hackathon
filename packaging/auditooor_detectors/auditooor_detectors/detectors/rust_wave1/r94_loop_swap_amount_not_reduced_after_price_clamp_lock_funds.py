"""
r94_loop_swap_amount_not_reduced_after_price_clamp_lock_funds.py

Flags swap/swap_step fns that clamp sqrt_price at the pool limit but do
not reduce the specified amount or refund the unused portion — the user
pays for the full amount while only a fraction is executed, and the
leftover tokens lock in the pool.

Source: Solodit #40243 (Cantina Marginal V1 LB Pool).
Class: swap-amount-not-reduced-after-price-clamp-lock-funds (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(^swap$|swap_pool|swap_step|exact_input|"
    r"swap_with_clamp|limit_price_swap)"
)
_CLAMP_RE = re.compile(
    fr"(sqrt_price_next\s*=\s*sqrt_price_limit|"
    fr"sqrtPriceNext\s*=\s*sqrtPriceLimit|"
    fr"price_clamped|priceClamped|"
    fr"if\s+{IDENT}sqrt_price_next\s*[<>]\s*{IDENT}sqrt_price_limit|"
    fr"clamp_sqrt_price|"
    fr"if\s+{IDENT}next_price\s+[<>]\s+{IDENT}limit_price)"
)
_AMOUNT_NOT_REDUCED_RE = re.compile(
    fr"(return\s+{IDENT}amount_specified\s*;|"
    fr"amount_in\s*=\s*{IDENT}amount_specified\s*;|"
    fr"ctx\.\s*amount_specified)"
)
_SAFE_RE = re.compile(
    fr"(amount_specified\s*-=|"
    fr"amountSpecified\s*-=|"
    fr"specified_amount\s*=\s*{IDENT}specified_amount\s*-|"
    fr"leftover_amount_to_user|refund_unused|"
    fr"\.\s*saturating_sub\s*\(\s*{IDENT}(amount_consumed|used_amount|used|executed)|"
    fr"\bamount\s*=\s*{IDENT}amount\s*\.\s*saturating_sub)"
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
        if _SAFE_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` clamps sqrt_price at the limit but "
                f"does not reduce the specified amount or refund the "
                f"unused portion — user pays full amount for a "
                f"fractional trade, extra tokens lock in the pool "
                f"(swap-amount-not-reduced-after-price-clamp-lock-funds). "
                f"See Solodit #40243 (Cantina Marginal V1 LB Pool)."
            ),
        })
    return hits

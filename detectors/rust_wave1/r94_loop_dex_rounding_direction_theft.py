"""
r94_loop_dex_rounding_direction_theft.py

Flags DEX/AMM fns computing amount-out / price / shares via a div that
rounds toward the USER instead of the POOL.

Source: Solodit #63649 (Sherlock / Dango DEX).

Heuristic:
  1. Fn name matches /(ask|bid|get|preview)_exact_amount_(in|out)|
     calc_amount_out|get_amount_out|quote_out|get_shares|
     compute_withdraw|preview_redeem/.
  2. Body computes `.checked_div(...)`, `/`, `mul_div`, or similar.
  3. Body does NOT contain round-up / ceiling cues:
     `mul_div_up`, `ceil_div`, `div_ceil`, `+ denom - 1 / denom`,
     `MulDiv::Up`, `rounding: Rounding::Up`, `round_up`.
  4. Body DOES mention amount_out / amount_in / shares (to disambig
     from non-swap math).
"""

from __future__ import annotations

import re

from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)


_FN_NAME_RE = re.compile(
    r"(?i)(ask|bid|get|preview)_?(exact_)?amount_?(in|out)|"
    r"calc_amount_?(in|out)|get_amount_?(in|out)|quote_?(in|out)|"
    r"get_shares|compute_withdraw|preview_redeem|preview_mint|"
    r"swap_?(out|in)|amount_?(out|in)_?for"
)

_DIV_RE = re.compile(
    r"\.checked_div\s*\(|"
    r"/\s*\w|"
    r"mul_div|mul_div_down|mul_div_floor"
)

_ROUND_UP_RE = re.compile(
    r"mul_div_up|ceil_div|div_ceil|round_up|RoundingMode::Up|"
    r"Rounding::Up|\+\s*\w+\s*-\s*1\s*\)\s*/\s*\w|"
    r"\(\w+\s*\+\s*\w+\s*-\s*1\s*\)\s*\/"
)

_AMOUNT_CONTEXT_RE = re.compile(
    r"amount_in|amount_out|reserves?|liquidity|shares|"
    r"numerator|denominator|fee"
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

        if not _DIV_RE.search(body_nc):
            continue
        if not _AMOUNT_CONTEXT_RE.search(body_nc):
            continue
        if _ROUND_UP_RE.search(body_nc):
            continue

        # Heuristic: for `*_exact_amount_out` (user asks for exactly X out,
        # pays amount_in) — amount_in math should round UP (pool-favorable).
        # For `*_exact_amount_in` (user pays X in, gets amount_out) —
        # amount_out math should round DOWN. We flag both as "check rounding
        # direction" because the mistake is common and class-wide.

        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` computes a DEX amount/share via division "
                f"with no round-up hint (mul_div_up / div_ceil / round_up). "
                f"Per-swap wei-dust accumulates in the user's favor → theft. "
                f"See Solodit #63649 (Dango DEX)."
            ),
        })
    return hits

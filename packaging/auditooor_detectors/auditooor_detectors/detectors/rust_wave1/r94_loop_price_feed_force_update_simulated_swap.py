"""
r94_loop_price_feed_force_update_simulated_swap.py

Flags price-oracle update fns that accept a `force_cur_block` (or
similar `force_*`) boolean param and run a simulated AMM swap when
true — attacker picks block boundary to skew cached price.

Source: Solodit #3858 (C4 Marginswap PriceAware).
Class: price-feed-force-update-simulated-swap (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(get_current_price|update_price|refresh_price|force_update_price|get_price_in_peg)")
_FORCE_ARG_RE = re.compile(
    r"\b(force_cur_block|force_update|force_refresh|force_block|force_now|force_\w+)\s*:\s*bool"
)
_AMM_SIMULATE_RE = re.compile(
    r"(simulate_swap|get_amount_out|get_amounts_out|getAmountsOut|k_swap|compute_swap|"
    r"router\.\s*quote|amm\.\s*quote|getAmountsIn)"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        sig_text = snippet_of(fn, source)
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        if not _FORCE_ARG_RE.search(sig_text + body_nc):
            continue
        if not _AMM_SIMULATE_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": sig_text[:200],
            "message": (
                f"pub fn `{name}` accepts `force_cur_block`-style "
                f"flag and runs a simulated AMM swap when true — "
                f"attacker picks block to skew cached price "
                f"(price-feed-force-update-simulated-swap). See "
                f"Solodit #3858 (Marginswap PriceAware)."
            ),
        })
    return hits

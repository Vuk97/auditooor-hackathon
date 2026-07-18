"""
r94_loop_v4_donate_sandwich_in_single_tx.py

Flags Uniswap-V4 style donate / distribute-fees fns that credit
in-range liquidity positions proportionally in the *same* tx
without a minimum-holding window / per-position cooldown — MEV
searcher sandwiches donate() (enter → receive → exit) atomically.

Source: Solodit #41758 (Sherlock Flayer).
Class: v4-donate-sandwich-in-single-tx (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(donate|distribute_fees|donate_in_range|"
    r"reward_in_range_liquidity|distribute_donation)"
)
# Touches in-range liquidity / fee growth.
_LIQ_RE = re.compile(
    r"(?i)(in_range_liquidity|activeLiquidity|"
    r"current_liquidity|fee_growth_inside|"
    r"fee_growth_global|liquidity_at_tick)"
)
# Safe: minimum-holding window / cooldown.
_COOLDOWN_RE = re.compile(
    fr"(?i)(min_hold_blocks|min_hold_duration|"
    fr"position\.created_at|created_at_block|"
    fr"jit_penalty|require\s*\(\s*{IDENT}block\s*-\s*{IDENT}start_block\s*>=|"
    fr"require\s*\(\s*{IDENT}timestamp\s*-\s*{IDENT}entered_at|"
    fr"cooldown|settlement_delay)"
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
        if not _LIQ_RE.search(body_nc):
            continue
        if _COOLDOWN_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` distributes donation / fees to "
                f"in-range liquidity positions atomically without a "
                f"minimum-holding / cooldown guard — MEV searcher "
                f"sandwiches in one tx (enter-receive-exit) "
                f"(v4-donate-sandwich-in-single-tx). "
                f"See Solodit #41758 (Sherlock Flayer)."
            ),
        })
    return hits

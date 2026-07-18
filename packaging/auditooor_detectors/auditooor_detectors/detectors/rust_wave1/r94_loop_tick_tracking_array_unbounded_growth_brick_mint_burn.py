"""
r94_loop_tick_tracking_array_unbounded_growth_brick_mint_burn.py

Flags mint/burn/harvest fns that push into a tick-tracking
collection without a length cap or cleanup path — attacker inflates
the array until iteration OOGs, bricking mint/burn/harvest for all
users.

Source: Solodit #27551 (Code4rena Canto LiquidityMining).
Class: tick-tracking-array-unbounded-growth-brick-mint-burn (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(
    r"(?i)(^mint$|^burn$|mint_liquidity|burn_liquidity|"
    r"harvest|claim_mining|update_tick_tracking|"
    r"accrue_mining_rewards)"
)
_ARR_PUSH_RE = re.compile(
    r"(tick_tracking|tickTracking|tick_tracking_|tickTracking_)\s*\.\s*push\s*\(|"
    r"tick_history\s*\.\s*push\s*\(|"
    r"position_ticks\s*\.\s*push\s*\("
)
_BOUND_CHECK_RE = re.compile(
    fr"assert\w*\s*!?\s*\(\s*\w*(tick_tracking|tickTracking)\s*\.\s*len\s*\(\s*\)\s*<=\s*{IDENT}MAX|"
    r"require\s*\(\s*\w*(tickTracking|tick_history)\.length\s*<=\s*\w*(MAX|CAP|LIMIT)|"
    r"MAX_TICK_TRACKING_LEN|"
    r"pop_stale_ticks|"
    r"compact_tick_tracking|"
    r"clean_up_stale_ticks"
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
        if not _ARR_PUSH_RE.search(body_nc):
            continue
        if _BOUND_CHECK_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn {name} pushes into a tick-tracking "
                f"collection without a length cap or cleanup — "
                f"attacker inflates the array until iteration OOGs, "
                f"bricking mint/burn/harvest "
                f"(tick-tracking-array-unbounded-growth-brick-mint-burn). "
                f"See Solodit #27551 (Code4rena Canto LiquidityMining)."
            ),
        })
    return hits

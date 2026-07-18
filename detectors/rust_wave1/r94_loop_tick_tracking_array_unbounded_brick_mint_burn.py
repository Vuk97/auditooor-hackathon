"""
r94_loop_tick_tracking_array_unbounded_brick_mint_burn.py

Flags LiquidityMining-style fns that push/append to a `tick_tracking`
array on every range-crossing WITHOUT a cap / eviction policy — the
array grows unbounded and later iterating over it bricks
mint/burn/harvest.

Source: Solodit #27551 (C4 Canto LiquidityMining).
Class: tick-tracking-array-unbounded-brick-mint-burn (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(r"(?i)(cross_tick|record_tick|track_tick|update_range|on_tick_cross|accrue_range)")
_UNBOUNDED_PUSH_RE = re.compile(
    r"(tick_tracking|tickTracking|tick_log|tickLog|range_crossings)\s*\.\s*(push|append|extend)"
)
_CAP_GUARD_RE = re.compile(
    r"(MAX_TICK_ENTRIES|tick_log\.len\s*\(\s*\)\s*<\s*\w+|"
    fr"require\s*\(\s*{IDENT}tick_tracking\.length\s*<\s*\w+|"
    r"evict_oldest|rotate_tick_log|TICK_LOG_LIMIT)"
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
        if not _UNBOUNDED_PUSH_RE.search(body_nc):
            continue
        if _CAP_GUARD_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` pushes to tick_tracking array on "
                f"every range crossing without a cap / eviction — "
                f"attacker dust-swaps to grow array until mint/burn "
                f"runs out of gas (tick-tracking-array-unbounded-"
                f"brick-mint-burn). See Solodit #27551 (Canto)."
            ),
        })
    return hits

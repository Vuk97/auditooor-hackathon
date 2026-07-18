"""
r94_loop_draw_reward_wrong_denominator.py

Flags prize/draw reward fns that divide by total_supply instead of
eligible_supply (or vice versa) — non-eligible holders dilute winners'
prize share.

Source: Solodit #25959 (PoolTogether draw wrong denominator).
Class: draw-reward-wrong-denominator (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(claim_prize|claim_draw|distribute_prize|award|payout_draw|calculate_prize)")
_DENOM_RE = re.compile(
    r"/\s*(total_supply|totalSupply)\s*\(\s*\)|"
    r"(prize|draw|reward)\s*\*\s*\w+\s*/\s*(total_supply|totalSupply)"
)
_ELIGIBLE_RE = re.compile(
    r"eligible_supply|eligibleSupply|total_weighted|totalWeighted|draw_supply|drawSupply|"
    r"qualified_supply|qualifiedSupply"
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
        if not _DENOM_RE.search(body_nc):
            continue
        if _ELIGIBLE_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` divides prize/draw reward by "
                f"total_supply without accounting for eligible_supply "
                f"— non-eligible holders dilute winners' share "
                f"(draw-reward-wrong-denominator). See Solodit #25959 "
                f"(PoolTogether)."
            ),
        })
    return hits

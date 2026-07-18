"""
r94_loop_self_liquidation_reward_harvest.py

Flags liquidate fns that pay a liquidation reward / bounty WITHOUT
checking that `caller != position.owner` — attacker can self-
liquidate to harvest the bounty.

Source: Solodit #35299 (C4 DittoETH).
Class: self-liquidation-reward-harvest (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(liquidate|execute_liquidation|seize_and_reward|call_liquidate)")
_REWARD_TRANSFER_RE = re.compile(
    r"(liquidation_reward|liquidation_bounty|incentive|liquidator_reward)\s*(=|\+=)|"
    r"\.transfer\s*\(\s*(liquidator|caller|msg_sender|env\.invoker)"
)
_SELF_GUARD_RE = re.compile(
    r"(caller\s*!=\s*\w*(owner|position\.owner|user)|"
    r"require\s*\(\s*\w*(owner|position\.owner)\s*!=\s*msg\.sender|"
    r"env\.invoker\s*\(\s*\)\s*!=\s*\w*(owner|position\.owner)|"
    r"assert[!_]?\s*\(\s*\w*(liquidator|caller)\s*!=\s*\w*(owner|position\.owner))"
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
        if not _REWARD_TRANSFER_RE.search(body_nc):
            continue
        if _SELF_GUARD_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` pays a liquidation reward without "
                f"guarding caller != position.owner — attacker can "
                f"self-liquidate to harvest bounty (self-liquidation-"
                f"reward-harvest). See Solodit #35299 (DittoETH)."
            ),
        })
    return hits

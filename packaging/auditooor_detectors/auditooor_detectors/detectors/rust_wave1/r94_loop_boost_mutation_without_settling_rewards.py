"""
r94_loop_boost_mutation_without_settling_rewards.py

Flags fns that change boost / lock / multiplier (setLockStatus,
extendLock, updateBoost) without calling update_reward /
settle_reward BEFORE the mutation — accrued rewards since last
update get retroactively multiplied at new boost.

Source: Solodit #19111 (Meta Boost.setLockStatus).
Class: boost-mutation-without-settling-rewards (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(set_lock_status|extend_lock|update_boost|set_boost|change_lock|set_multiplier)")
_MUTATES_BOOST_RE = re.compile(
    r"(lock_status|boost_factor|multiplier|boost_of|lock_duration)\s*=|"
    r"self\.(lock_status|boost_factor|multiplier)\s*=|"
    r"boosts\s*\.\s*insert"
)
_SETTLES_REWARDS_FIRST_RE = re.compile(
    r"(update_reward|settle_reward|accrue_reward|claim_rewards)\s*\("
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
        if not _MUTATES_BOOST_RE.search(body_nc):
            continue
        if _SETTLES_REWARDS_FIRST_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` mutates boost/lock/multiplier "
                f"without calling update_reward first — accrued "
                f"rewards since last update get retroactively "
                f"multiplied (boost-mutation-without-settling-"
                f"rewards). See Solodit #19111 (Meta Boost)."
            ),
        })
    return hits

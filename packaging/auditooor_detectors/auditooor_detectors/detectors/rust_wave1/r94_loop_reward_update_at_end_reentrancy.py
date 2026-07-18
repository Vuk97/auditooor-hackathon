"""
r94_loop_reward_update_at_end_reentrancy.py

Flags redeem / exit / withdraw fns where the LAST call is
`_update_account_rewards` / `update_reward_map` that transfers
reward tokens — ERC777-like reward tokens hook-reenter at that
point with inconsistent state.

Source: Solodit #35121 (Sherlock Notional Leveraged Vaults).
Class: reward-update-at-end-reentrancy (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(redeem|exit|withdraw|unwind_position|close_position)")
_UPDATE_REWARDS_RE = re.compile(
    r"(_update_account_rewards|update_reward_map|distribute_rewards|transfer_reward_tokens|pay_rewards)\s*\("
)
_REENTRANCY_GUARD_RE = re.compile(
    r"non_reentrant|nonReentrant|ReentrancyGuard|reentrancy_lock|reentrancy_guard"
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
        if not _UPDATE_REWARDS_RE.search(body_nc):
            continue
        if _REENTRANCY_GUARD_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` calls `_update_account_rewards` / "
                f"`distribute_rewards` without a reentrancy guard — "
                f"ERC777-like reward token transfer triggers hook "
                f"that reenters with inconsistent state "
                f"(reward-update-at-end-reentrancy). See Solodit "
                f"#35121 (Notional Leveraged Vaults)."
            ),
        })
    return hits

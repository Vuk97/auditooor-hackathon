"""
r94_loop_reward_multiplier_reset_by_griefer.py

Flags permissionless `handle_balance_update` / `update_user_weight`
fns that reset a user's multiplier/boost when called with a zero/
stale delta — anyone can grief a user's multiplier to 1.

Source: Solodit #31611 (Pashov Increment SMRewardDistributor).
Class: reward-multiplier-reset-by-griefer (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(
    r"(?i)(handle_balance_update|update_user_weight|refresh_multiplier|"
    r"sync_user|recompute_boost|update_stake_weight)"
)
_RESETS_MULTIPLIER_RE = re.compile(
    r"(multiplier|boost|weight|stake_weight)\s*=\s*1\b|"
    r"reset_multiplier\s*\(|"
    r"set_multiplier\s*\([^)]*\s*,\s*1\s*\)"
)
_CALLER_GATED_RE = re.compile(
    r"require_auth\s*\(\s*(user|target|account)|"
    r"only_user\s*\(\s*\w+\s*\)|"
    r"only_self|"
    r"assert[!_]?eq\s*\(\s*caller\s*,\s*(user|target|account)|"
    r"caller\s*==\s*(user|target|account)"
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
        if not _RESETS_MULTIPLIER_RE.search(body_nc):
            continue
        if _CALLER_GATED_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` resets user multiplier to 1 "
                f"without gating on caller == user — griefer pins "
                f"victim's multiplier low (reward-multiplier-reset-"
                f"by-griefer). See Solodit #31611 (Increment)."
            ),
        })
    return hits

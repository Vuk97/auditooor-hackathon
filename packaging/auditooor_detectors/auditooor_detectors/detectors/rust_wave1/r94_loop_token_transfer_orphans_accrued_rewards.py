"""
r94_loop_token_transfer_orphans_accrued_rewards.py

Flags token `_update` / `transfer` / `on_before_transfer` hooks that
move balances but don't settle / update per-user accrued rewards
(`reward_per_token_stored`, `last_reward_index`) for BOTH sender and
receiver first — sender's lastRewardPerToken stays at newer value
than new balance → future accrual orphaned.

Source: Solodit #5899 (Stakehouse GiantMevAndFeesPool).
Class: token-transfer-orphans-accrued-rewards (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(_update|on_transfer|before_transfer|after_transfer|handle_transfer|token_transfer)")
_MUTATES_BALANCE_RE = re.compile(
    r"(balances|balance_of|_balances|\.balance)\s*\[\s*(sender|from|owner)\s*\]\s*[-=]|"
    r"self\.balances\s*\.\s*insert\s*\(\s*&?(sender|from|owner)|"
    r"balance_of_mut\s*\(\s*\&?(sender|from|owner)"
)
_SETTLE_REWARDS_RE = re.compile(
    r"(_update_reward|update_rewards?|settle_reward|accrue_reward|snapshot_reward|"
    r"last_reward_per_token_paid\s*=|reward_per_token_paid\s*\[)"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        if not _MUTATES_BALANCE_RE.search(body_nc):
            continue
        if _SETTLE_REWARDS_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"fn `{name}` mutates token balance during transfer "
                f"hook without settling accrued rewards for sender/"
                f"receiver — sender's lastRewardPerToken drifts, "
                f"future accrual orphans (token-transfer-orphans-"
                f"accrued-rewards). See Solodit #5899 (Stakehouse)."
            ),
        })
    return hits

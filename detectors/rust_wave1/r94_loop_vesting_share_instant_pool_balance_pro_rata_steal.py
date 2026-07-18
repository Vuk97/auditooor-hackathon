"""
r94_loop_vesting_share_instant_pool_balance_pro_rata_steal.py

Flags vesting/bonus release fns that compute each user's share from the
instantaneous pool balance × pro-rata (shares / total_shares) — an
attacker deposits just before withdraw and siphons accrued bonus tokens.

Source: Solodit #2490 (Code4rena Rubicon BathBuddy).
Class: vesting-share-instant-pool-balance-pro-rata-steal (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(
    r"(?i)(release|withdraw|claim_bonus|claimBonus|"
    r"release_bonus|releaseBonus|claim_vested|claimVested|"
    r"payout_share|payoutShare|release_pro_rata)"
)
_INSTANT_BALANCE_RE = re.compile(
    r"(balance_of\s*\(\s*(self|address\s*\(\s*this\s*\))|"
    r"balanceOf\s*\(\s*address\s*\(\s*this\s*\)|"
    r"pool_balance\s*\(\s*\)|"
    r"poolBalance\s*\(\s*\)|"
    r"pool\s*\.\s*balance)"
)
_SHARE_CALC_RE = re.compile(
    fr"(shares\s*\*\s*{IDENT}(balance|total_pool_amount|vested)|"
    fr"user_shares\s*\*\s*{IDENT}(balance|total_pool)|"
    r"shares_of\s*\(\s*\w+\s*\)\s*\*|"
    fr"{IDENT}share\s*\/\s*{IDENT}total_shares)"
)
_SAFE_RE = re.compile(
    r"(snapshot_balance|snapshotBalance|"
    r"stored_total_bonus|storedTotalBonus|"
    r"cumulative_reward_per_share|accRewardPerShare|"
    r"vested_at_time|checkpointed_total|bonus_reserve)"
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
        if not _INSTANT_BALANCE_RE.search(body_nc):
            continue
        if not _SHARE_CALC_RE.search(body_nc):
            continue
        if _SAFE_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn {name} computes each user's release share from "
                f"instantaneous pool balance × pro-rata — attacker deposits "
                f"just before withdraw and siphons accrued bonus tokens "
                f"(vesting-share-instant-pool-balance-pro-rata-steal). "
                f"See Solodit #2490 (Code4rena Rubicon BathBuddy)."
            ),
        })
    return hits

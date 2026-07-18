"""
r94_loop_incentivized_erc20_recursive_liquidity_reward_amplification.py

Flags reward-claim / pending-reward fns on yield-bearing
IncentivizedERC20 / wrapped-yield tokens that compute per-user
rewards from `balanceOf` * accRewardPerShare without rejecting
accounts that are themselves contract pools / LPs holding the
same underlying — attacker recursively wraps/restakes to multiply
pending rewards beyond issued emissions.

Source: Solodit #61562 (Cyfrin Paladin Valkyrie).
Class: incentivized-erc20-recursive-liquidity-reward-amplification (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(pending_reward|pending_rewards|claim_reward|"
    r"claim_rewards|harvest|compute_rewards|accrue_reward|"
    r"update_reward|reward_of)"
)
# Computes from balance * acc/share.
_RPS_COMPUTE_RE = re.compile(
    fr"(?i)(balance_of\s*\([^)]*\)\s*\*\s*{IDENT}acc\w*|"
    fr"user_balance\s*\*\s*{IDENT}rewards_per_share|"
    fr"balance_of\s*\([^)]*\)\s*\*\s*{IDENT}reward_per_share|"
    fr"balance\s*\*\s*{IDENT}reward_index|"
    fr"shares\s*\*\s*{IDENT}reward_per_share|"
    fr"\bbal\w*\s*\*\s*{IDENT}reward_per_share|"
    fr"\bbal\w*\s*\*\s*{IDENT}acc\w*|"
    fr"reward_per_share\s*\*\s*{IDENT}bal\w*|"
    fr"rewardPerShare\s*\*\s*{IDENT}bal\w*|"
    r"accRewardPerShare\s*\(\s*\)|"
    r"rewards_per_share\s*\(\s*\))"
)
# Safe: excludes wrapper pools / blacklists / deposit tracking.
_GUARD_RE = re.compile(
    r"(?i)(is_pool_or_vault|is_blacklisted|"
    r"pool_address_registry\.contains|"
    r"tracked_deposit_balance|deposit_principal|"
    r"external_balance_of\s*\([^)]*owner_of_deposits|"
    r"require\s*\(\s*!\s*is_pool|"
    r"require\s*\(\s*!\s*is_vault|"
    r"snapshot_at_deposit|"
    r"user_deposit_ledger)"
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
        if not _RPS_COMPUTE_RE.search(body_nc):
            continue
        if _GUARD_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` computes rewards from "
                f"`balance_of(user) * rewardPerShare` without "
                f"excluding wrapper pools / LP contracts that hold "
                f"the underlying — attacker recursively wraps/restakes "
                f"to multiply pending rewards beyond issued emissions "
                f"(incentivized-erc20-recursive-liquidity-reward-amplification). "
                f"See Solodit #61562 (Cyfrin Paladin Valkyrie)."
            ),
        })
    return hits

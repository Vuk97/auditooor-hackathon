"""
r94_loop_rewards_update_after_external_transfer_reentrancy_steal.py

Flags `redeem_shares` / `withdraw_vault_shares` fns that transfer
tokens to the user and then call `update_account_rewards` /
`accrue_rewards_for` at the end — receiver's hook can re-enter
the vault and double-claim rewards using the pre-update share
balance. Correct ordering is: update rewards → transfer tokens.

Source: Solodit #35121 (Sherlock Notional Leveraged Vaults Pendle PT).
Class: rewards-update-after-external-transfer-reentrancy-steal (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(
    r"(?i)(redeem_shares|redeem_vault_shares|withdraw_vault_shares|"
    r"exit_vault|unwind_position|close_leveraged_position|"
    r"burn_vault_shares)"
)
# Updates rewards AFTER external transfer.
_BAD_ORDER_RE = re.compile(
    r"(?i)(transfer(_from)?\s*\([\s\S]{0,200}?\)\s*;\s*[\s\S]{0,200}?"
    r"update_account_rewards|updateAccountRewards|"
    r"accrue_rewards_for|distribute_rewards_for|"
    r"claim_reward_debt_update|sync_reward_checkpoint)",
)
# Safe: update rewards BEFORE transfer, or uses reentrancy guard + CEI.
_SAFE_ORDER_RE = re.compile(
    r"(?i)(update_account_rewards[\s\S]{0,300}?transfer(_from)?\s*\(|"
    r"updateAccountRewards[\s\S]{0,300}?(transfer|_burn)\s*\(|"
    r"non_reentrant|nonReentrant|reentrancy_guard|"
    r"_status\s*=\s*ENTERED|mutex_acquire)"
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
        if not _BAD_ORDER_RE.search(body_nc):
            continue
        if _SAFE_ORDER_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` transfers tokens to the user BEFORE "
                f"calling update_account_rewards, with no reentrancy "
                f"guard — receive-hook re-enters to double-claim "
                f"rewards using pre-update share balance "
                f"(rewards-update-after-external-transfer-reentrancy-steal). "
                f"See Solodit #35121 (Sherlock Notional Leveraged Vaults)."
            ),
        })
    return hits

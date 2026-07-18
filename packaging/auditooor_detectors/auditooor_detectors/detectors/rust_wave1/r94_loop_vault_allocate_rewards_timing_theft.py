"""
r94_loop_vault_allocate_rewards_timing_theft.py

Flags `allocate` / `distribute_rewards` fns that distribute pending
reward tokens pro-rata to CURRENT shares — attacker sandwich-
deposits, calls allocate, withdraws, skimming accrued undistributed
rewards.

Source: Solodit #10773 (OpenZeppelin Origin Dollar VaultCore).
Class: vault-allocate-rewards-timing-theft (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(r"(?i)(allocate|distribute_rewards|rebalance_rewards|accrue_allocate)")
_PRO_RATA_RE = re.compile(
    r"(pending_rewards|unallocated_rewards|accrued_rewards|yield_buffer)\s*(?:\(\s*\))?\s*[*/]\s*"
    fr"(user_shares|{IDENT}balance\w*|shares_of|share_of)"
)
_SNAPSHOT_BASIS_RE = re.compile(
    r"(shares_at_allocate_start|last_allocate_shares|pre_deposit_shares|"
    r"snapshot_shares|cooldown_gate|lock_until_allocate)"
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
        if not _PRO_RATA_RE.search(body_nc):
            continue
        if _SNAPSHOT_BASIS_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` distributes accrued rewards pro-"
                f"rata to CURRENT shares with no cooldown / "
                f"snapshot gate — attacker deposits, calls allocate, "
                f"withdraws to skim yield (vault-allocate-rewards-"
                f"timing-theft). See Solodit #10773 (Origin Dollar)."
            ),
        })
    return hits

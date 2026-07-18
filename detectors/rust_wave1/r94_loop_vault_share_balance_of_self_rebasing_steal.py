"""
r94_loop_vault_share_balance_of_self_rebasing_steal.py

Flags vault deposit / withdraw fns that compute user shares as
`amount * totalShares / balanceOf(self)` using the *current*
ERC20 balanceOf of the vault. If the underlying token rebases
(AMPL, stETH), an attacker deposits just before a positive
rebase and withdraws right after, siphoning the rebase delta
from other depositors.

Source: Solodit #35735 (Code4rena Thorchain).
Class: vault-share-balance-of-self-rebasing-steal (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(deposit|mint_shares|join_vault|stake_lp|"
    r"withdraw|redeem_shares|burn_shares)"
)
_BALANCE_OF_SELF_RE = re.compile(
    fr"(?i)(amount\s*\*\s*{IDENT}total_shares\s*\/\s*{IDENT}balance_of\s*\(|"
    fr"amount\s*\*\s*totalShares\s*\/\s*{IDENT}balanceOf\s*\(|"
    fr"amount\s*\*\s*total_supply\s*\/\s*balance_of_self|"
    fr"amount\s*\*\s*totalSupply\s*\/\s*{IDENT}balanceOf\s*\(|"
    fr"{IDENT}shares\s*=\s*{IDENT}amount\s*\*\s*{IDENT}total_shares\s*\/\s*{IDENT}balance_of\s*\(|"
    fr"{IDENT}shares\s*=\s*{IDENT}amount\s*\*\s*{IDENT}total_supply\s*\/\s*{IDENT}balance_of\s*\()"
)
# Safe: uses a tracked / snapshot asset balance, not live balanceOf.
_TRACKED_RE = re.compile(
    r"(?i)(tracked_balance|storedBalance|internalBalance|"
    r"totalAssets\s*\(\s*\)|total_assets\s*\(\s*\)|"
    r"principal_tracked|underlyingTotal|"
    r"snapshot_asset_balance|stored_asset_balance|"
    r"checkpointed_balance)"
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
        if not _BALANCE_OF_SELF_RE.search(body_nc):
            continue
        if _TRACKED_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` computes shares using "
                f"`balanceOf(self)` instead of a tracked asset "
                f"balance — rebasing tokens (AMPL, stETH) change the "
                f"denominator silently, attacker deposits before a "
                f"positive rebase and withdraws after to siphon "
                f"(vault-share-balance-of-self-rebasing-steal). "
                f"See Solodit #35735 (Code4rena Thorchain)."
            ),
        })
    return hits

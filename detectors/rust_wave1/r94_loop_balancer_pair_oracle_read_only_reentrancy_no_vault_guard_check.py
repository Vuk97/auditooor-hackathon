"""
r94_loop_balancer_pair_oracle_read_only_reentrancy_no_vault_guard_check.py

Flags oracle fns that read BalancerVault.getPoolTokens /
get_pool_tokens to price LP tokens without first probing the
Vault's reentrancy lock (e.g. calling `manageUserBalance`
no-op). During a joinPool/exitPool callback, read-only
reentrancy returns a stale pool snapshot and the oracle is
manipulated.

Source: Solodit #18493 (Sherlock Blueberry BalancerPairOracle).
Class: balancer-pair-oracle-read-only-reentrancy-no-vault-guard-check (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(get_price|get_lp_price|get_pool_price|"
    r"price_of|latest_price|compute_lp_value|fetch_lp_price)"
)
_VAULT_READ_RE = re.compile(
    fr"(?i)(get_pool_tokens|getPoolTokens|"
    fr"{IDENT}vault\s*\.\s*get_pool|vault\s*\.\s*getPool|"
    fr"balancer_vault\s*\.\s*get_pool_tokens|"
    fr"IVault\s*\(\s*\w+\s*\)\s*\.\s*getPoolTokens)"
)
_VAULT_GUARD_RE = re.compile(
    r"(?i)(manage_user_balance|manageUserBalance|"
    r"ensure_not_reentered|ensureNotReentered|"
    r"vault_reentrancy_guard|vaultReentrancyGuard|"
    r"check_vault_not_entered|checkVaultNotEntered|"
    r"Vault::ensureNotInVaultContext|"
    r"balancer_reentrancy_check)"
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
        if not _VAULT_READ_RE.search(body_nc):
            continue
        if _VAULT_GUARD_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` reads BalancerVault.getPoolTokens "
                f"without first probing the Vault's reentrancy lock "
                f"(e.g. a no-op `manageUserBalance` call) — during "
                f"joinPool callback the read returns a stale snapshot "
                f"and attacker premature-liquidates "
                f"(balancer-pair-oracle-read-only-reentrancy-no-vault-guard-check). "
                f"See Solodit #18493 (Sherlock Blueberry BalancerPairOracle)."
            ),
        })
    return hits

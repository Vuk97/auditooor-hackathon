"""
r94_loop_vault_asset_injection_without_share_mint.py

Flags fns that transfer/mint underlying tokens INTO the vault
contract without minting matching shares — total_assets inflates,
share price jumps, prior depositors capture the injection.

Source: Solodit #35298 (DittoETH yDUSD).
Class: vault-asset-injection-without-share-mint (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(
    r"(?i)(distribute_reward|inject_assets|mint_to_vault|distribute_yield|"
    r"accrue_yield|harvest|notify_reward_amount|donate)"
)
_MINTS_TO_VAULT_RE = re.compile(
    r"\.transfer\s*\(\s*(vault_address|address\(this\)|self\.addr|env\.current_contract_address|address_of\s*\(\s*self\s*\))|"
    r"\._mint\s*\(\s*(vault_address|address\(this\)|self\.addr)|"
    r"\.mint\s*\(\s*(vault_address|address\(this\)|self\.addr)"
)
_SHARE_MINT_RE = re.compile(
    r"_mint\s*\(\s*(user|to|receiver|msg_sender)|"
    r"share_token\s*\.\s*mint|internal_mint_shares|self\.mint_shares"
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
        if not _MINTS_TO_VAULT_RE.search(body_nc):
            continue
        if _SHARE_MINT_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` injects assets into the vault "
                f"without minting matching shares — total_assets "
                f"inflates, share price jumps, prior depositors "
                f"capture the injection (vault-asset-injection-"
                f"without-share-mint). See Solodit #35298 (DittoETH)."
            ),
        })
    return hits

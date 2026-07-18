"""
r94_loop_onerc721received_reentrancy_collateral_shares_manipulation.py

Flags `onERC721Received` / on_erc721_received handlers that mutate
collateral-config / share / accounting state AND then make an
external call (safeTransferFrom, callback, approval) before the
state is finalised. Nested callbacks re-enter the same handler
and inflate/deflate config shares.

Source: Solodit #32262 (Code4rena Revert Lend V3Vault).
Class: onerc721received-reentrancy-collateral-shares-manipulation (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(
    r"(?i)(on_erc721_received|onERC721Received|"
    r"on_erc1155_received|onERC1155Received)"
)
# Mutates collateral / shares / config.
_STATE_MUTATION_RE = re.compile(
    r"(?i)(collateral_config|collateralConfig|"
    r"collateral_shares|collateralShares|"
    fr"{IDENT}shares\s*\[|{IDENT}balance\s*\[|"
    r"update_shares|record_collateral|"
    r"token_configs\s*\[|tokenConfigs\s*\[|"
    fr"positions\s*\[\s*{IDENT}token_id\s*\])"
)
# Followed by an external call within same body.
_EXTERNAL_CALL_RE = re.compile(
    r"(?i)(safe_transfer_from\s*\(|safeTransferFrom\s*\(|"
    r"\.call\s*\(|\.call_raw\s*\(|"
    r"invoke_contract|invoke_contract_with_gas|"
    r"approve\s*\(|set_approval_for_all\s*\(|"
    r"transfer_from\s*\()"
)
# Safe: nonReentrant / reentrancy_guard / checks-effects-interactions done properly.
_REENTRANCY_GUARD_RE = re.compile(
    r"(?i)(non_reentrant|nonReentrant|"
    r"reentrancy_guard|reentrancy_lock|"
    r"ReentrancyGuard|mutex|"
    r"guard_entered|enter_reentrancy_guard|"
    r"_status\s*=\s*ENTERED)"
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
        if not _STATE_MUTATION_RE.search(body_nc):
            continue
        if not _EXTERNAL_CALL_RE.search(body_nc):
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
                f"pub fn `{name}` mutates collateral / share state "
                f"and then makes an external call in the same body "
                f"without a reentrancy guard — nested ERC721/1155 "
                f"callbacks re-enter and inflate/deflate config "
                f"shares "
                f"(onerc721received-reentrancy-collateral-shares-manipulation). "
                f"See Solodit #32262 (Code4rena Revert Lend V3Vault)."
            ),
        })
    return hits

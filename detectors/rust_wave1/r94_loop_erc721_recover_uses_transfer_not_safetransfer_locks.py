"""
r94_loop_erc721_recover_uses_transfer_not_safetransfer_locks.py

Flags admin recoverERC721 / sweepNFT helpers that call a plain
`.transfer(...)` on an ERC721 handle or use a non-safe transfer
to a contract address. OZ ERC721 has no `transfer(address,uint256)`
method (only transferFrom / safeTransferFrom) — tokens end up
permanently locked or the call reverts.

Source: Solodit #29457 (Code4rena Dopex UniV3LiquidityAMO).
Class: erc721-recover-uses-transfer-not-safetransfer-locks (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(recover_erc721|recoverERC721|sweep_nft|sweepNft|"
    r"withdraw_erc721|withdrawERC721|rescue_nft|rescueNft|"
    r"emergency_recover_nft|recover_position_nft)"
)
_NON_SAFE_TRANSFER_RE = re.compile(
    fr"(?i)(\bnft\s*\.\s*transfer\s*\(|"
    fr"\berc721\s*\.\s*transfer\s*\(|"
    fr"\b{IDENT}IERC721\s*\(\s*\w+\s*\)\s*\.\s*transfer\s*\(|"
    fr"\btransfer\s*\(\s*{IDENT}(to|recipient|receiver)\s*,\s*{IDENT}token_id\s*\))"
)
_SAFE_TRANSFER_RE = re.compile(
    r"(?i)(safeTransferFrom|safe_transfer_from)"
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
        if not _NON_SAFE_TRANSFER_RE.search(body_nc):
            continue
        if _SAFE_TRANSFER_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` uses a plain `.transfer(...)` to "
                f"move an ERC721 NFT — OZ ERC721 has no such method "
                f"(only transferFrom / safeTransferFrom), call "
                f"reverts or tokens end up permanently locked "
                f"(erc721-recover-uses-transfer-not-safetransfer-locks). "
                f"See Solodit #29457 (Code4rena Dopex UniV3LiquidityAMO)."
            ),
        })
    return hits

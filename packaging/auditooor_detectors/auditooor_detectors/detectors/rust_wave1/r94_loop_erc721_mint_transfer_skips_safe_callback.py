"""
r94_loop_erc721_mint_transfer_skips_safe_callback.py

Flags mint / transfer fns on ERC721-style contracts that use
plain `_mint` / `_transfer` instead of `_safeMint` /
`_safeTransfer`. Recipient's onERC721Received is never invoked,
so contract recipients cannot refuse or react — tokens can end
up stuck or bypass recipient invariants.

Source: Solodit #18215 (TrailOfBits Opyn Controller).
Class: erc721-mint-transfer-skips-safe-callback (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(mint_nft|mint_token|mint_erc721|"
    r"transfer_nft|transfer_erc721|"
    r"mint_to|\bmint\b|\btransfer\b|"
    r"deposit_nft|stake_nft|record_nft_position)"
)
# Use of non-safe _mint / _transfer / transferFrom against a contract recipient.
_NON_SAFE_RE = re.compile(
    fr"(?i)(\b_mint\s*\(\s*{IDENT}(to|recipient|receiver)|"
    fr"\b_transfer\s*\(\s*{IDENT}(from|sender)|"
    fr"\btransferFrom\s*\(\s*{IDENT}(from|sender|payer)|"
    fr"nft\s*\.\s*transfer_from\s*\(|"
    fr"erc721\s*\.\s*mint\s*\(|"
    fr"\.\s*mint\s*\(\s*{IDENT}(to|recipient))"
)
_SAFE_RE = re.compile(
    r"(?i)(_safe_mint|_safeMint|"
    r"safe_mint\s*\(|safeMint\s*\(|"
    r"_safe_transfer|_safeTransfer|"
    r"safe_transfer_from\s*\(|safeTransferFrom\s*\()"
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
        if not _NON_SAFE_RE.search(body_nc):
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
                f"pub fn `{name}` mints / transfers ERC721 via "
                f"non-safe path (_mint / _transfer / transferFrom) — "
                f"recipient's onERC721Received is never invoked, "
                f"contract recipients cannot refuse and tokens may "
                f"become stuck or bypass recipient invariants "
                f"(erc721-mint-transfer-skips-safe-callback). "
                f"See Solodit #18215 (TrailOfBits Opyn Controller)."
            ),
        })
    return hits

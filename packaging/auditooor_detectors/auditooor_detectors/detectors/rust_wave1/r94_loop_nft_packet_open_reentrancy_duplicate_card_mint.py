"""
r94_loop_nft_packet_open_reentrancy_duplicate_card_mint.py

Flags NFT packet / booster open fns that mint reward NFTs to the
caller via an external callback BEFORE committing the packet's
burn state (or without a reentrancy guard). Attacker's
onERC721Received reenters the open call and opens the same
packet twice, duplicating cards.

Source: Solodit #62592 (Pashov Audit Group RipIt CardAllocationPool).
Class: nft-packet-open-reentrancy-duplicate-card-mint (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(
    r"(?i)(open_packet|authorizedOpenPacket|authorized_open_packet|"
    r"open_booster|open_pack|redeem_packet|"
    r"reveal_pack|claim_pack_rewards)"
)
# Body mints cards via safe_mint / _mint / safeTransferFrom before burn state commit.
_MINT_BEFORE_COMMIT_RE = re.compile(
    r"(?i)((_safeMint|_safe_mint|safeMint|safe_mint|_mint|"
    r"safeTransferFrom|safe_transfer_from)\s*\([\s\S]{0,200}?\)\s*;[\s\S]{0,300}?"
    r"(packet\.opened\s*=\s*true|save_packet|commit_burn|burn_packet|_burn|is_open\s*=\s*true))"
)
# Safe: reentrancy guard or burn/commit BEFORE mint.
_SAFE_RE = re.compile(
    r"(?i)(non_reentrant|nonReentrant|reentrancy_guard|"
    r"_status\s*=\s*ENTERED|mutex|"
    r"(packet\.opened\s*=\s*true|commit_burn|_burn|burn_packet)[\s\S]{0,200}?(safeMint|_safe_mint|safeTransferFrom|safe_transfer_from))"
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
        if not _MINT_BEFORE_COMMIT_RE.search(body_nc):
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
                f"pub fn `{name}` safe-mints NFT cards to caller via "
                f"external callback BEFORE committing the packet's "
                f"burn state, and has no reentrancy guard — caller's "
                f"onERC721Received reenters to open the same packet "
                f"twice "
                f"(nft-packet-open-reentrancy-duplicate-card-mint). "
                f"See Solodit #62592 (Pashov Audit Group RipIt)."
            ),
        })
    return hits

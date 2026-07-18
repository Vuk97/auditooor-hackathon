"""
r94_loop_nft_multiple_auctions_same_token_escrow_lock.py

Flags createAuction / list_nft fns that store auction metadata keyed
by auction_id WITHOUT checking that the NFT is not already escrowed
in another active auction — owner creates two auctions, second
wins the NFT leaving first's bidders stranded.

Source: Solodit #1576 (C4 Foundation NFTMarketReserveAuction).
Class: nft-multiple-auctions-same-token-escrow-lock (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(r"(?i)(create_auction|create_reserve_auction|list_nft|open_auction|start_auction)")
_CREATE_RE = re.compile(
    fr"(auctions|reserve_auctions|listings)\s*\[\s*{IDENT}auction_id\s*\]\s*=|"
    fr"\.insert\s*\(\s*{IDENT}auction_id\s*,"
)
_EXISTING_GUARD_RE = re.compile(
    fr"(existing_auction_id\s*\[|nft_locked_in\s*\[|active_auction_of\s*\[|"
    fr"\.contains_key\s*\(\s*\&?\s*{IDENT}token_id|require\s*!\s*(auctions|listings)\s*\[\s*{IDENT}token_id|"
    fr"is_listed\s*\(\s*{IDENT}token_id\s*\)\s*==\s*false)"
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
        if not _CREATE_RE.search(body_nc):
            continue
        if _EXISTING_GUARD_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` creates an auction entry without "
                f"checking if the NFT is already escrowed in another "
                f"active auction — owner creates A and B, B wins "
                f"escrow leaving A's bidders stranded (nft-multiple-"
                f"auctions-same-token-escrow-lock). See Solodit #1576 "
                f"(Foundation)."
            ),
        })
    return hits

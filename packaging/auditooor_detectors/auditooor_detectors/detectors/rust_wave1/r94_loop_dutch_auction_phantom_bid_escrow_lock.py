"""
r94_loop_dutch_auction_phantom_bid_escrow_lock.py

Flags dutch-auction bid fns that write a pending-bid record
(`best_bid_for_listing[id] = bid`) EVEN when the path for a
dutch-auction type only admits one valid bid that should settle
immediately — accumulated phantom bids lock honest escrow.

Source: Solodit #46405 (Cantina Kim Exchange).
Class: dutch-auction-phantom-bid-escrow-lock (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(bid|bid_for_nft|_bid_for_auction|place_bid)")
_STORES_BID_RE = re.compile(
    r"(best_bid_for_listing|best_bid|pending_bid|bid_escrow|stored_bid)\s*\[[^\]]*\]\s*="
)
_DUTCH_DETECT_RE = re.compile(
    r"(auction_type\s*==\s*AuctionType::Dutch|listing_type\s*==\s*ListingType::Dutch|"
    r"is_dutch|dutch_auction\s*==\s*true|listing\.dutch\s*=\s*true)"
)
_IMMEDIATE_SETTLE_RE = re.compile(
    r"(settle_listing\s*\(|_settle_dutch\s*\(|finalize_dutch\s*\(|close_listing\s*\()"
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
        if not _STORES_BID_RE.search(body_nc):
            continue
        if not _DUTCH_DETECT_RE.search(body_nc):
            continue
        if _IMMEDIATE_SETTLE_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` stores pending bid on a dutch "
                f"auction (only one valid bid should exist) without "
                f"immediately settling — phantom bids accumulate, "
                f"honest escrow locked (dutch-auction-phantom-bid-"
                f"escrow-lock). See Solodit #46405 (Kim Exchange)."
            ),
        })
    return hits

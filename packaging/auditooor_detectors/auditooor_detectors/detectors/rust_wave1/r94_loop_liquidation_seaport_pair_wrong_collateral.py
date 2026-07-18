"""
r94_loop_liquidation_seaport_pair_wrong_collateral.py

Flags liquidate fns that build a Seaport-style `OrderParameters` /
`OfferItem` / `ConsiderationItem` pair where the `offer` side has
the real collateral NFT but the `consideration` side contains a
FAKE/HELPER NFT alongside settlement token — buyers can manipulate
pair so real NFT is stuck in contract.

Source: Solodit #25798 (Astaria Clearinghouse).
Class: liquidation-seaport-pair-wrong-collateral (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(liquidate|list_collateral|start_dutch_auction|list_on_seaport)")
_SEAPORT_PAIR_RE = re.compile(
    r"(OfferItem|ConsiderationItem|OrderParameters)[\s\S]{0,200}?"
    r"(fake_nft|helper_nft|clearing_house_nft|synthetic_collateral|proxy_nft)"
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
        if not _SEAPORT_PAIR_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` builds a Seaport order pair with a "
                f"fake/helper NFT in consideration — buyers manipulate "
                f"pair to lock real collateral in contract "
                f"(liquidation-seaport-pair-wrong-collateral). See "
                f"Solodit #25798 (Astaria)."
            ),
        })
    return hits

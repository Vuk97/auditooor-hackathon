"""
r94_loop_rental_stop_no_caller_verification.py

Flags `stop_rental` / `cancel_rental` / `reclaim_rental` fns that
end a rental and move the NFT back to lender but DON'T verify
caller is renter, lender, or protocol.

Source: Solodit #30525 (C4 reNFT Stop.sol).
Class: rental-stop-no-caller-verification (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(stop_rental|cancel_rental|reclaim_rental|end_rental|close_rental)")
_TRANSFERS_NFT_RE = re.compile(
    r"(nft|erc721|token)\s*\.\s*(transfer_from|safeTransferFrom|transfer)\s*\("
)
_OWNER_CHECK_RE = re.compile(
    r"(caller\s*==\s*\w*(renter|lender)|"
    r"require\s*\(\s*msg\.sender\s*==\s*\w*(renter|lender)|"
    r"env\.invoker\s*\(\s*\)\s*==\s*\w*(renter|lender)|"
    r"assert[!_]?eq\s*\(\s*caller\s*,\s*\w*(renter|lender)|"
    r"only_renter_or_lender|\b_onlyAuthorized\b)"
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
        if not _TRANSFERS_NFT_RE.search(body_nc):
            continue
        if _OWNER_CHECK_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` stops rental and moves NFT without "
                f"verifying caller is renter or lender — anyone "
                f"stops active rentals and reclaims NFT "
                f"(rental-stop-no-caller-verification). See Solodit "
                f"#30525 (reNFT Stop)."
            ),
        })
    return hits

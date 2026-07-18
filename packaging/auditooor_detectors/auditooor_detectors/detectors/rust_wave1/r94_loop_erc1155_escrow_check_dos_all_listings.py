"""
r94_loop_erc1155_escrow_check_dos_all_listings.py

Flags `_is_listing_valid` / `check_listing` fns that compare
`erc1155.balance_of(marketplace, token_id) >= listing.amount` for
the CURRENT listing — but a shared balance is drained by one
listing invalidating unrelated listings (cascade DOS).

Source: Solodit #46408 (Cantina Kim Exchange).
Class: erc1155-escrow-check-dos-all-listings (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(r"(?i)(_is_listing_valid|check_listing|validate_listing|is_listed_valid)")
_BALANCE_CHECK_RE = re.compile(
    fr"balance_of\s*\(\s*{IDENT}(marketplace|self|address\(this\)|self\.addr)[^)]{{0,80}}?,\s*{IDENT}(token_id|listing\.token_id)"
    fr"[\s\S]{{0,80}}?>=\s*{IDENT}(listing\.amount|amount|required)"
)
_DEDICATED_ESCROW_RE = re.compile(
    r"(escrow_of|per_listing_balance|reserved_balance|locked_for_listing|"
    r"listing_escrow\[|reservations\[)"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        if not _BALANCE_CHECK_RE.search(body_nc):
            continue
        if _DEDICATED_ESCROW_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"fn `{name}` checks listing validity via "
                f"balance_of(marketplace, token_id) >= listing.amount "
                f"— shared balance drained by one listing cascades "
                f"to invalidate unrelated listings (DOS) "
                f"(erc1155-escrow-check-dos-all-listings). See "
                f"Solodit #46408 (Kim Exchange)."
            ),
        })
    return hits

"""
r94_loop_clob_order_erc777_reentrancy.py

Flags CLOB / LOB `place_order` / `cancel_order` fns that call
`token.transfer` / `safe_transfer_from` BEFORE updating internal
order state — ERC777 sender hook re-enters to manipulate order
book.

Source: Solodit #56836/#55167/#53799 (MixBytes XPress/Hanji).
Class: clob-order-erc777-reentrancy (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(place_order|cancel_order|submit_order|post_order|match_order)")
_TRANSFER_THEN_UPDATE_RE = re.compile(
    r"(token\.transfer|safe_transfer_from|\.transfer_from\s*\()[\s\S]{0,300}?"
    r"(orders\s*\[|order_book\s*\.\s*(insert|remove)|self\.orders|self\.order_book)"
)
_REENTRANCY_GUARD_RE = re.compile(
    r"non_reentrant|nonReentrant|ReentrancyGuard|reentrancy_lock"
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
        if not _TRANSFER_THEN_UPDATE_RE.search(body_nc):
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
                f"pub fn `{name}` transfers tokens before updating "
                f"order-book state with no reentrancy guard — ERC777 "
                f"hook re-enters to manipulate orders (clob-order-"
                f"erc777-reentrancy). See Solodit #56836 (XPress LOB)."
            ),
        })
    return hits

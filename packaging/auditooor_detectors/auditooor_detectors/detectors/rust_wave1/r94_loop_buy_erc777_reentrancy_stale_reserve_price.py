"""
r94_loop_buy_erc777_reentrancy_stale_reserve_price.py

Flags pair/pool `buy` / `sell` / `swap` fns that transfer the
buy-token (ERC20-style) BEFORE updating reserves, with no
non_reentrant guard — ERC777 hook re-enters buy, sees stale
reserve price.

Source: Solodit #6096 (C4 Caviar Pair.buy).
Class: buy-erc777-reentrancy-stale-reserve-price (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(buy|sell|swap|purchase|exchange)")
_TRANSFER_THEN_UPDATE_RE = re.compile(
    r"(\.transfer\s*\(|safe_transfer\s*\()[\s\S]{0,300}?"
    r"(reserve0\s*=|reserve1\s*=|self\.reserves\s*=|update_reserves\s*\()"
)
_REENTRANCY_GUARD_RE = re.compile(
    r"non_reentrant|nonReentrant|ReentrancyGuard|reentrancy_lock|_before_op_called"
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
                f"reserves with no reentrancy guard — ERC777 hook "
                f"re-enters buy at stale reserve price, discount "
                f"purchase (buy-erc777-reentrancy-stale-reserve-"
                f"price). See Solodit #6096 (Caviar Pair)."
            ),
        })
    return hits

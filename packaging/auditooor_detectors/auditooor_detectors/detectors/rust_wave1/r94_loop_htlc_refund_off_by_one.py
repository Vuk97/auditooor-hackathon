"""
r94_loop_htlc_refund_off_by_one.py

Flags HTLC refund fns that use strict `<` between current time and
timelock, when the refund should include the timelock boundary (`<=`).

Source: Hexens Train Protocol LYSWP2-family.
Class: htlc-refund-off-by-one (both).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment, IDENT, CALL,
)

_FN_NAME_RE = re.compile(r"(?i)^(refund|reclaim|timeout|cancel_lock|withdraw_refund)$")
_STRICT_LT_RE = re.compile(
    fr"(now|current_ts|block_timestamp|env\.ledger\(\))\s*<\s*{IDENT}\.?(timelock|expiration|deadline)|"
    fr"require!?\s*\([^)]*(now|block_timestamp)\s*<\s*{IDENT}\.?(timelock|expiration|deadline)[^=]"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    root = tree.root_node
    for fn, _impl in functions_in_contractimpl(root, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        # refund path should allow `now >= timelock`. If guard is `now < timelock` (strict lt)
        # or a require that inverts refund eligibility, flag.
        if _STRICT_LT_RE.search(body_nc):
            line, col = line_col(fn)
            hits.append({
                "severity": "medium",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:200],
                "message": (
                    f"pub fn `{name}` (refund-family) uses strict `<` "
                    f"between timestamp and timelock. At exactly timelock "
                    f"(now == timelock) the refund is neither permitted "
                    f"nor blocked — off-by-one. Use `<=`/`>=`. See Hexens "
                    f"Train Protocol."
                ),
            })
    return hits

"""
r94_loop_pending_withdrawal_amount_reset_by_view.py

Flags getter/view-style fns (names like get_*, view_*, total_*,
read_*) that MUTATE state — specifically write to
`_pending_withdrawal_amount` / `pending_amount` / similar.

Source: Solodit #51636 (Halborn Tagus Labs V2).
Class: pending-withdrawal-amount-reset-by-view (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)^(get_\w+|view_\w+|total_\w+|read_\w+|fetch_\w+|query_\w+)$")
_WRITES_PENDING_RE = re.compile(
    r"(_pending_withdrawal_amount|pending_withdrawal_amount|pending_amount|"
    r"_pending_amount|withdrawal_queue_total)\s*=\s*(0|\w+)"
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
        if not _WRITES_PENDING_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` is named as a getter but mutates "
                f"`_pending_withdrawal_amount` / similar — anyone "
                f"calling it wipes pending withdrawals "
                f"(pending-withdrawal-amount-reset-by-view). See "
                f"Solodit #51636 (Tagus Labs)."
            ),
        })
    return hits

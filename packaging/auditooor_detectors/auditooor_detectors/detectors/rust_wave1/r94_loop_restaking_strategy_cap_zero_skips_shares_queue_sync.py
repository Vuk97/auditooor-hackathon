"""
r94_loop_restaking_strategy_cap_zero_skips_shares_queue_sync.py

Flags LRT admin fns that set/remove a restaking strategy cap but
do NOT call a corresponding `updateTotalShares` / `sync_queue` /
`rebalance` / `adjust_total_shares` — setting cap to 0 leaves the
already-held shares unchanged and the withdrawal queue unadjusted,
so user withdrawals exceed allocated amount on the next rebalance.

Source: Solodit #30897 (Sherlock Rio Network).
Class: restaking-strategy-cap-zero-skips-shares-queue-sync (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(
    r"(?i)(set_strategy_cap|remove_strategy|update_strategy_cap|"
    r"set_cap|set_strategy_allocation|disable_strategy|"
    r"zero_strategy|retire_strategy)"
)
# Assignment to 0 / removal.
_ZERO_OP_RE = re.compile(
    fr"(?i)(=\s*0\b|=\s*0u\w*|\.\s*remove\s*\(|\.\s*set\s*\(\s*&?{IDENT}cap_key\s*,\s*0)"
)
# Safe: sync shares / queue / rebalance.
_SYNC_RE = re.compile(
    r"(?i)(update_total_shares|adjust_total_shares|sync_shares|"
    r"refresh_total_shares|decrement_total_shares|"
    r"update_withdrawal_queue|sync_queue|process_queue|"
    r"rebalance|update_queue_allocation|prune_queue)"
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
        if not _ZERO_OP_RE.search(body_nc):
            continue
        if _SYNC_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` zeros / removes a restaking "
                f"strategy cap without calling update_total_shares / "
                f"update_withdrawal_queue / rebalance — the already-"
                f"held shares and pending queue remain unsynced, user "
                f"withdrawals exceed allocation at next rebalance "
                f"(restaking-strategy-cap-zero-skips-shares-queue-sync). "
                f"See Solodit #30897 (Sherlock Rio Network)."
            ),
        })
    return hits

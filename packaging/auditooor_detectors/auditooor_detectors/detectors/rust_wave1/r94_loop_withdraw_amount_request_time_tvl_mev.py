"""
r94_loop_withdraw_amount_request_time_tvl_mev.py

Flags withdraw-queue `request_withdraw` fns that compute the
`assets_owed` from CURRENT live `total_tvl()` / `total_assets()`
/ oracle price — attacker sandwiches the request block, extracts
TVL delta.

Source: Solodit #33491 (C4 Renzo WithdrawQueue).
Class: withdraw-amount-request-time-tvl-mev (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(
    r"(?i)(request_withdraw|queue_withdraw|submit_withdraw|register_withdraw|"
    r"init_withdraw|start_withdraw)"
)
_LIVE_TVL_RE = re.compile(
    r"(total_tvl|total_assets|calculate_tvl|get_tvl|current_tvl|"
    r"oracle_price|price_oracle\.get|tvl\(\))\s*\("
)
_SNAPSHOT_BASIS_RE = re.compile(
    r"(snapshot_tvl|cached_tvl|frozen_tvl|tvl_at_epoch|last_epoch_tvl|"
    r"settle_price_snapshot|tvl_snapshot_block)"
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
        if not _LIVE_TVL_RE.search(body_nc):
            continue
        if _SNAPSHOT_BASIS_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` computes assets_owed from LIVE "
                f"total_tvl()/oracle at request time — attacker "
                f"sandwiches the request to extract TVL delta "
                f"(withdraw-amount-request-time-tvl-mev). "
                f"See Solodit #33491 (Renzo WithdrawQueue)."
            ),
        })
    return hits

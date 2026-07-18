"""
r94_loop_withdraw_fee_no_claimed_flag.py

Flags withdraw_fee / withdraw_reward / claim_fee fns that transfer
protocol fees WITHOUT setting a `claimed/withdrawn` flag afterwards —
caller replays until pool drained.

Source: Solodit #8851 (RabbitHole Erc20Quest).
Class: withdraw-fee-no-claimed-flag (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(withdraw_fee|withdraw_reward|claim_fee|collect_fee|harvest_fee|withdraw_protocol_fee)")
_TRANSFER_RE = re.compile(
    r"\.transfer\s*\(|token\.transfer|safe_transfer|_transfer\s*\(|\.send\s*\("
)
_FLAG_SET_RE = re.compile(
    r"(fee_withdrawn|claimed|paid|has_withdrawn|withdrawn|fee_claimed)\s*=\s*true|"
    r"self\.(fee_withdrawn|claimed|has_withdrawn|fee_claimed)\s*=\s*true|"
    r"\.(insert|set|write)\s*\([^)]*(fee_withdrawn|claimed|withdrawn)"
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
        if not _TRANSFER_RE.search(body_nc):
            continue
        if _FLAG_SET_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` transfers protocol fees without "
                f"setting a `withdrawn/claimed` flag — caller replays "
                f"until pool drained (withdraw-fee-no-claimed-flag). "
                f"See Solodit #8851 (RabbitHole)."
            ),
        })
    return hits

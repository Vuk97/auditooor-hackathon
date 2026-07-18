"""
r94_loop_deposit_and_bridge_unlock_bypass.py

Flags deposit_and_bridge / mint_and_bridge fns that mint shares and
call bridge.send in the SAME fn but don't enforce the shareUnlockTime
/ cooldown that the regular withdraw path uses.

Source: Solodit #36518 (Ion Protocol).
Class: deposit-and-bridge-unlock-bypass (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(
    r"(?i)(deposit_and_bridge|mint_and_bridge|deposit_and_send|bridge_deposit)"
)
_MINT_RE = re.compile(
    r"(_mint\s*\(|\.mint\s*\(|share_token\s*\.\s*mint|mint_shares\s*\()"
)
_BRIDGE_CALL_RE = re.compile(
    r"(bridge\s*\.\s*send|bridge\s*\.\s*transfer|bridge_nft|bridge_out|"
    r"cross_chain_send|teleport\s*\()"
)
_COOLDOWN_CHECK_RE = re.compile(
    r"(share_unlock_time|shareUnlockTime|unlock_time|cooldown|lockup|"
    r"vest_until|unlock_at)"
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
        if not _MINT_RE.search(body_nc):
            continue
        if not _BRIDGE_CALL_RE.search(body_nc):
            continue
        if _COOLDOWN_CHECK_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` mints shares and bridges them out in "
                f"one fn without checking share_unlock_time — users "
                f"bypass the lockup via bridge exit "
                f"(deposit-and-bridge-unlock-bypass). See Solodit "
                f"#36518 (Ion Protocol)."
            ),
        })
    return hits

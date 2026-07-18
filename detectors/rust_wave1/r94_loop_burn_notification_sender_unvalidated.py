"""
r94_loop_burn_notification_sender_unvalidated.py

Flags TON/Jetton-style `op::burn_notification` / `mint_notification`
handler fns that update `total_supply` without asserting the sender
address equals the expected master/minter address.

Source: Solodit #61876 (Quantstamp XDAO).
Class: sender-address-not-validated-burn (both).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment, IDENT, CALL,
)

_FN_NAME_RE = re.compile(r"(?i)(recv_internal|on_burn_notification|on_mint_notification|handle_burn_notify|handle_notify)")
_SUPPLY_WRITE_RE = re.compile(r"total_supply\s*[-+]=|total_supply\s*=\s*\w")
_SENDER_CHECK_RE = re.compile(
    fr"sender_address\s*==\s*({IDENT}jetton_master|{IDENT}minter|{IDENT}owner)|"
    fr"require!?\s*\([^)]*sender_address\s*==|"
    fr"assert!?\s*\([^)]*sender_address\s*==|"
    fr"throw_unless\s*\([^)]*sender_address"
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
        if not _SUPPLY_WRITE_RE.search(body_nc):
            continue
        if _SENDER_CHECK_RE.search(body_nc):
            continue
        # Require burn_notification context
        if not re.search(r"burn_notification|mint_notification|notification_op", body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` handles a burn/mint notification and "
                f"writes `total_supply` without asserting "
                f"`sender_address == jetton_master/minter/owner`. "
                f"Spoofed notification manipulates supply. See Solodit "
                f"#61876 (XDAO)."
            ),
        })
    return hits

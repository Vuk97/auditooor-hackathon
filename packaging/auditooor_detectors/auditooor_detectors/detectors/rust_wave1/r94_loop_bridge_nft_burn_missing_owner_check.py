"""
r94_loop_bridge_nft_burn_missing_owner_check.py

Flags bridge / messenger fns that burn / transfer out a caller-
supplied NFT id (ticket, badge, position) without asserting the
caller actually owns that id. Attacker specifies another user's
NFT id and drains the bridge payout.

Source: Solodit #64140 (Code4rena Megapot JackpotBridgeManager).
Class: bridge-nft-burn-missing-owner-check (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(bridge_out|bridge_burn|burn_and_bridge|"
    r"lock_and_send|release_on_eid|send_cross_chain|"
    r"bridge_ticket|bridge_nft|redeem_on_dst)"
)
_BURN_RE = re.compile(
    fr"(?i)(\b_burn\s*\(\s*{IDENT}token_id|burn\s*\(\s*{IDENT}token_id|"
    fr"\bticket\s*\.\s*burn\s*\(|"
    fr"nft\s*\.\s*burn\s*\(\s*{IDENT}token_id|"
    fr"burn_nft\s*\(\s*{IDENT}token_id|"
    fr"transfer_from\s*\(\s*{IDENT}owner\s*,\s*{IDENT}bridge\s*,\s*{IDENT}token_id|"
    fr"safe_transfer_from\s*\(\s*{IDENT}owner\s*,\s*{IDENT}bridge\s*,\s*{IDENT}token_id)"
)
_OWNER_CHECK_RE = re.compile(
    fr"(?i)(owner_of\s*\(\s*{IDENT}token_id\s*\)\s*==\s*{IDENT}(sender|caller|invoker|msg\.sender)|"
    fr"ownerOf\s*\(\s*{IDENT}token_id\s*\)\s*==\s*{IDENT}msg\.sender|"
    fr"require\s*\(\s*{IDENT}ownerOf\s*\(\s*{IDENT}token_id\s*\)\s*==\s*{IDENT}msg\.sender|"
    fr"assert\w*\s*!?\s*\(\s*{IDENT}owner_of\s*\(\s*{IDENT}token_id\s*\)\s*==\s*{IDENT}caller|"
    fr"require_auth\s*\(\s*&?\s*{IDENT}(owner|caller|invoker)|"
    fr"_is_approved_or_owner|isApprovedOrOwner|"
    fr"require\s*\(\s*{IDENT}ownerOf\s*\(\s*{IDENT}token_id\s*\)\s*==\s*{IDENT}_msgSender)"
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
        if not _BURN_RE.search(body_nc):
            continue
        if _OWNER_CHECK_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` burns / transfers out a caller-"
                f"supplied NFT id without asserting the caller owns "
                f"it (ownerOf check or require_auth) — attacker passes "
                f"another user's id and drains the bridge payout "
                f"(bridge-nft-burn-missing-owner-check). "
                f"See Solodit #64140 (Code4rena Megapot JackpotBridgeManager)."
            ),
        })
    return hits

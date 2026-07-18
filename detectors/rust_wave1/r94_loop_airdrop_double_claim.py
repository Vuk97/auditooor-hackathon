"""
r94_loop_airdrop_double_claim.py

Flags airdrop / distribution claim fns that transfer tokens to user
without setting a per-user claimed flag (or with a flag-set AFTER the
transfer — reentrancy window).

Source: common pattern across Solodit; Rust side of `airdrop-double-claim`.
"""

from __future__ import annotations

import re

from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)


_FN_NAME_RE = re.compile(
    r"(?i)^(claim|claim_?airdrop|claim_?tokens|claim_?reward|"
    r"claim_?distribution|redeem_?airdrop|distribute|airdrop_?to)$"
)

_TRANSFER_RE = re.compile(
    r"\.transfer\s*\(|\.try_transfer\s*\(|token::transfer|"
    r"spl_token::instruction::transfer|\.mint_to\s*\(|\.credit\s*\("
)

# A claim-tracker set BEFORE any transfer. Lax: any write to a
# claimed/has_claimed/processed flag in the fn.
_CLAIM_FLAG_SET_RE = re.compile(
    r"(claimed|has_claimed|is_claimed|processed|redeemed|user_claimed|"
    r"airdrop_claimed)\s*[:\[]?[^=]*?=\s*(true|1u)|"
    r"set_claim(ed)?\s*\(|"
    r"mark_claim(ed)?\s*\(|"
    r"\.set\s*\([^)]*(Claim|Claimed|Redeemed|Processed)"
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

        # Must actually transfer tokens
        transfer_m = _TRANSFER_RE.search(body_nc)
        if not transfer_m:
            continue

        flag_set_m = _CLAIM_FLAG_SET_RE.search(body_nc)
        if flag_set_m is None:
            # No claim flag at all — strong signal
            line, col = line_col(fn)
            hits.append({
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:200],
                "message": (
                    f"pub fn `{name}` transfers airdrop/reward tokens but "
                    f"never sets a per-user claimed flag. Users can call "
                    f"it repeatedly — double-claim drain. Set a flag BEFORE "
                    f"the transfer (CEI order)."
                ),
            })
            continue

        # Flag is set — make sure it's BEFORE the transfer
        if flag_set_m.start() > transfer_m.start():
            line, col = line_col(fn)
            hits.append({
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:200],
                "message": (
                    f"pub fn `{name}` sets the claimed-flag AFTER transferring "
                    f"tokens. Reentrancy / callback can re-enter before the "
                    f"flag is set — double-claim. Set flag before transfer (CEI)."
                ),
            })
    return hits

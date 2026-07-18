"""
r94_loop_redeem_burn_before_transfer_erc777_hook_reenter_drain.py

Flags stablecoin `redeem` fns that burn the stable first then
transfer collateral to the user — if collateral is an ERC777-
style token with a `tokensToSend` / `tokensReceived` hook, the
callback re-enters `redeem` using the already-partially-updated
state and drains extra collateral.

Source: Solodit #20815 (Code4rena Angle Protocol Redeemer).
Class: redeem-burn-before-transfer-erc777-hook-reenter-drain (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(^redeem$|^_redeem$|redeem_stablecoin|"
    r"redeem_shares_for_collateral|swap_stable_for_collateral|"
    r"burn_and_redeem)"
)
# Burn → external transfer of collateral pattern (state mutation before transfer).
_BURN_THEN_TRANSFER_RE = re.compile(
    fr"(?i)((_burn|burn_from|burn\s*\(\s*{IDENT}(ag_token|usd|stable))\s*\([\s\S]{{0,200}}?\)\s*;[\s\S]{{0,300}}?"
    fr"(transfer(_from)?\s*\(\s*{IDENT}collateral|"
    fr"safeTransfer\s*\(\s*{IDENT}collateral|"
    fr"safe_transfer\s*\(\s*{IDENT}collateral|"
    fr"token\.transfer\s*\(\s*{IDENT}user|"
    fr"collateral\.transfer\s*\())"
)
_GUARD_RE = re.compile(
    r"(?i)(non_reentrant|nonReentrant|reentrancy_guard|"
    r"ReentrancyGuard|mutex|_status\s*=\s*ENTERED|"
    r"lock_acquire|redeem_lock)"
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
        if not _BURN_THEN_TRANSFER_RE.search(body_nc):
            continue
        if _GUARD_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` burns the stablecoin then "
                f"transfers collateral to the user in the same body "
                f"with no reentrancy guard — an ERC777 collateral's "
                f"`tokensReceived` hook re-enters redeem with "
                f"partially-updated state, draining extra collateral "
                f"(redeem-burn-before-transfer-erc777-hook-reenter-drain). "
                f"See Solodit #20815 (Code4rena Angle Protocol Redeemer)."
            ),
        })
    return hits

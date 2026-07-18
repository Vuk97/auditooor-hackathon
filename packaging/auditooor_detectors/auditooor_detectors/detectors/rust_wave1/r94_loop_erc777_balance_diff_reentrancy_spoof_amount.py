"""
r94_loop_erc777_balance_diff_reentrancy_spoof_amount.py

Flags bridge / tokenmanager `receive_token` fns that measure
received amount via pre/post balance diff AND have no
non_reentrant guard — ERC777 sender hook can re-enter to deposit
additional tokens between balance snapshots, spoofing amount.

Source: Solodit #28760 (Axelar TokenManager).
Class: erc777-balance-diff-reentrancy-spoof-amount (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(receive_token|deposit_token|lock_token|on_token_received|accept_tokens)")
_BALANCE_DIFF_RE = re.compile(
    r"(balance_of|balance)\s*\([^;]{0,80}\)\s*-\s*(balance_before|prev_bal|before_bal|initial_bal)"
)
_REENTRANCY_GUARD_RE = re.compile(
    r"non_reentrant|nonReentrant|ReentrancyGuard|reentrancy_lock|reentrancy_guard"
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
        if not _BALANCE_DIFF_RE.search(body_nc):
            continue
        if _REENTRANCY_GUARD_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` measures received amount via pre/"
                f"post balance diff with no reentrancy guard — ERC777 "
                f"sender hook re-enters to deposit mid-check, diff "
                f"over-counts (erc777-balance-diff-reentrancy-spoof-"
                f"amount). See Solodit #28760 (Axelar TokenManager)."
            ),
        })
    return hits

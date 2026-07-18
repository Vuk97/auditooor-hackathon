"""
r94_loop_restaking_withdraw_dos_erc20_buffer_overflow.py

Flags `completeQueuedWithdrawal` / exit fns that push assets into
an ERC-20 withdrawal buffer and revert / error when the buffer's
cap is reached — once the cap is hit every subsequent withdrawal
is blocked forever.

Source: Solodit #33494 (Code4rena Renzo OperatorDelegator).
Class: restaking-withdraw-dos-erc20-buffer-overflow (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(complete_queued_withdrawal|complete_withdrawal|"
    r"finalize_withdrawal|claim_withdrawal|settle_withdrawal|"
    r"fill_erc20_buffer|fill_withdraw_buffer)"
)
# Must touch a buffer / cap.
_BUFFER_RE = re.compile(
    r"(?i)(erc20_buffer|withdraw_buffer|withdrawal_buffer|"
    r"buffer_cap|buffer_max|buffer_limit|deposit_queue_buffer)"
)
# Safe: cap-full branch that falls through / skips without revert.
_FALLTHROUGH_RE = re.compile(
    fr"(?i)(buffer_full|if\s+{IDENT}buffer\w*\s*(>=|>|==)\s*{IDENT}cap|"
    fr"if\s+{IDENT}remaining_cap\s*(==|<=)\s*0|"
    fr"buffer_space\s*>\s*0\s*\?|"
    fr"min\s*\(\s*{IDENT}buffer_space|buffer_saturation|"
    fr"skip_if_full|leftover\s*=\s*amount\s*\.\s*saturating_sub)"
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
        if not _BUFFER_RE.search(body_nc):
            continue
        if _FALLTHROUGH_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` writes withdrawn assets into an "
                f"ERC-20 withdrawal buffer without a fall-through "
                f"path for when the buffer is full — once buffer cap "
                f"is reached, every subsequent completion reverts, "
                f"permanent DOS on exits "
                f"(restaking-withdraw-dos-erc20-buffer-overflow). "
                f"See Solodit #33494 (Code4rena Renzo)."
            ),
        })
    return hits

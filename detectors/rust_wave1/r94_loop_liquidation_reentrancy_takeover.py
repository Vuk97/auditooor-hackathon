"""
r94_loop_liquidation_reentrancy_takeover.py

Flags liquidate / take_over_debt style fns with no nonReentrant guard
AND a sibling fn in the same module that calls the external token
path (triggering reentry).

Source: Solodit #27395 (Real Wagmi).
Class: liquidation-reentrancy-takeover (both).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)

_FN_NAME_RE = re.compile(r"(?i)(take_?over_?debt|liquidate|liquidate_position|execute_?liquidation)")
_EXTERNAL_CALL_RE = re.compile(
    r"\.transfer\s*\(|\.transferFrom\s*\(|\.call\s*\(|\.delegatecall\s*\(|"
    r"token\.send|\.safeTransfer"
)
_GUARD_RE = re.compile(r"nonReentrant|non_reentrant|reentrancy_guard|ReentrancyGuard")


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
        if _GUARD_RE.search(body_nc):
            continue
        if not _EXTERNAL_CALL_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` (liquidation/take-over-debt path) "
                f"makes external token calls with no nonReentrant guard. "
                f"Reentrant sibling fn (transfer / delegatecall) can run "
                f"mid-liquidation. See Solodit #27395 (Real Wagmi)."
            ),
        })
    return hits

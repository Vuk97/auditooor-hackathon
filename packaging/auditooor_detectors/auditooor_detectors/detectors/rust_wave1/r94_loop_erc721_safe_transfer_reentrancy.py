"""
r94_loop_erc721_safe_transfer_reentrancy.py

Flags fns that call `safe_transfer_from` / `safe_mint` on a user-
controlled ERC721-like target, and mutate state AFTER the call.

Source: Solodit #44334 (MixBytes EYWA).
Class: erc721-safe-transfer-reentrancy (both).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)

_CALL_RE = re.compile(
    r"\.safe_?transfer_?from\s*\(|safeTransferFrom\s*\(|"
    r"\.safe_?mint\s*\(|safeMint\s*\("
)
_STATE_MUT_AFTER_RE = re.compile(
    r"(storage|self|state)\s*\.\s*\w+\s*=|\w+\s*\[[^\]]+\]\s*=|\w+\s*[-+]=\s*|"
    r"\.\s*(insert|push|set|update|remove|write)\s*\("
)
_GUARD_RE = re.compile(r"nonReentrant|non_reentrant|reentrancy_guard|ReentrancyGuard")


def run(tree, source: bytes, filepath: str):
    hits = []
    root = tree.root_node
    for fn, _impl in functions_in_contractimpl(root, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        if _GUARD_RE.search(body_nc):
            continue
        call_m = _CALL_RE.search(body_nc)
        if call_m is None:
            continue
        # State mutation AFTER the safe_transfer_from call
        tail = body_nc[call_m.end():]
        if not _STATE_MUT_AFTER_RE.search(tail):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` calls safe_transfer_from / safe_mint "
                f"THEN mutates state, with no reentrancy-guard modifier. "
                f"ERC721 receiver hook reenters before state commit. "
                f"See Solodit #44334 (MixBytes EYWA)."
            ),
        })
    return hits

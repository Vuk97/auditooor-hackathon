"""
r94_loop_htlc_timelock_delta_unenforced.py

Flags HTLC commit/add_lock/create fns that accept a `timelock` /
`expiration` arg without asserting a minimum delta from `now`.

Source: Hexens Train Protocol (LYSWP2-family).
Class: htlc-timelock-delta-unenforced (both).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment, IDENT, CALL,
)

_FN_NAME_RE = re.compile(r"(?i)^(commit|add_?lock|create_?htlc|initiate_?htlc|lock)$")
_TIMELOCK_PARAM_RE = re.compile(r"\btimelock\b|\bexpiration\b|\bdeadline\b|\btimeout\b|\bexpire_?at\b")
_DELTA_CHECK_RE = re.compile(
    fr"timelock\s*-\s*(now|current_ts|block_timestamp|env\.ledger\(\))|"
    fr"timelock\s*>=\s*(now|block_timestamp|env\.ledger\(\))\s*\+|"
    fr"(now|block_timestamp|env\.ledger\(\))\s*\+\s*MIN_\w*(DELTA|TIMELOCK)|"
    fr"require!?\s*\([^)]*timelock\s*-\s*{IDENT}(now|timestamp)|"
    fr"MIN_TIMELOCK_DELTA"
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
        fn_text = text_of(fn, source)
        if not _TIMELOCK_PARAM_RE.search(fn_text):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        if _DELTA_CHECK_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` accepts a `timelock`/`expiration`/`deadline` "
                f"arg without asserting a minimum delta from current time "
                f"(e.g., `timelock >= now + MIN_TIMELOCK_DELTA`). LP can "
                f"lock a near-immediate expiry to grief the solver. See "
                f"Hexens Train Protocol LYSWP2-family."
            ),
        })
    return hits

"""
r94_loop_perps_liquidation_state_flip.py

Flags perp-liquidation fns that apply a settlement diff to the position
without asserting the resulting position-direction matches the prior one.

Source: Solodit #57697 (Code4rena Starknet Perpetual).
Class: perps-liquidation-state-flip (both).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)

_FN_NAME_RE = re.compile(r"(?i)(liquidate|deleverage|force_close|liquidate_position)")
_POSITION_SIZE_RE = re.compile(
    r"position\.size|\.size\s*=|position_size|"
    r"new_size|delta_size"
)
_DIRECTION_CHECK_RE = re.compile(
    r"position\.is_long|position\.direction|is_long\(\)|direction\(\)|"
    r"position\.side|require!?\s*\([^)]*(is_long|direction|side)|"
    r"assert_direction|same_side|check_direction_preserved"
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
        if not _POSITION_SIZE_RE.search(body_nc):
            continue
        if _DIRECTION_CHECK_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` applies a size-diff to a position but "
                f"doesn't assert that position direction (long/short) is "
                f"preserved. Liquidation can flip a long to short (or "
                f"reverse). See Solodit #57697 (Starknet Perpetual)."
            ),
        })
    return hits

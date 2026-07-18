"""
r94_loop_stableswap_precision_overflow.py

Flags stableswap/curve-style fns using intermediate Uint256-width accumulators
that can overflow when dealing with high-decimal tokens (18+ decimals) and
large amounts. Solodit #55000 (MANTRA, Code4rena).
"""

from __future__ import annotations

import re

from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)


_FN_NAME_RE = re.compile(
    r"(?i)(stableswap|curve_d|curve_y|calc_d|calc_y|"
    r"calculate_stable|stable_invariant|stable_math|get_d|get_y)"
)

# Multiplication of amounts followed by division with no widening
_NARROW_MUL_DIV_RE = re.compile(
    r"\b(U256|Uint256|u256)::from\s*\([^)]*\)\s*\*\s*\b(U256|Uint256|u256)::from|"
    # Or direct u128 * u128 in a pool-math context
    r"pool_balance\s*\*\s*pool_balance|"
    r"reserve\w*\s*\*\s*reserve\w*"
)

_WIDENING_RE = re.compile(
    r"U512|u512|Uint512|widening_mul|mul_div_down|mul_div_up|"
    r"checked_mul\s*\([^)]*\)\s*\?\s*\.\s*checked_div"
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

        if not _NARROW_MUL_DIV_RE.search(body_nc):
            continue
        if _WIDENING_RE.search(body_nc):
            continue

        line, col = line_col(fn)
        hits.append({
            "severity": "medium",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` is a stableswap/curve math fn using "
                f"Uint256 (or direct u128*u128) for intermediate accumulators. "
                f"High-decimal tokens (18+) with large pool balances overflow "
                f"Uint256 during invariant calc. Use Uint512 / widening_mul / "
                f"mul_div_down helpers. See Solodit #55000 (MANTRA)."
            ),
        })
    return hits

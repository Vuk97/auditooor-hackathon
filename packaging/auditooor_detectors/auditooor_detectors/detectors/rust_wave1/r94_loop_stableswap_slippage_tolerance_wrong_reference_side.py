"""
r94_loop_stableswap_slippage_tolerance_wrong_reference_side.py

Flags stableswap `provide_liquidity` / `add_liquidity` fns whose
slippage-tolerance check compares `actual_deposit` against the
POOL's total balance instead of the user's nominal deposit amount.

Source: Solodit #54986 (C4 MANTRA stableswap provide_liquidity).
Class: stableswap-slippage-tolerance-wrong-reference-side (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(r"(?i)(provide_liquidity|add_liquidity|deposit_stable|stable_deposit)")
_WRONG_REF_RE = re.compile(
    r"(actual_deposit|actual_received)\s*[<>]=?\s*\w*(total_pool|pool_balance|total_supply)\s*\*|"
    fr"assert_slippage_tolerance\s*\(\s*{IDENT}actual[^)]*,\s*{IDENT}pool_{IDENT}total"
)
_CORRECT_REF_RE = re.compile(
    r"(actual_deposit|actual_received)\s*[<>]=?\s*\w*(nominal|requested|expected)\s*\*|"
    fr"assert_slippage_tolerance\s*\(\s*{IDENT}actual[^)]*,\s*\w*(expected|nominal|requested)"
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
        if not _WRONG_REF_RE.search(body_nc):
            continue
        if _CORRECT_REF_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` compares actual_deposit against "
                f"POOL's total balance (not the user's nominal "
                f"deposit) for slippage tolerance — tolerance check "
                f"misapplied (stableswap-slippage-tolerance-wrong-"
                f"reference-side). See Solodit #54986 (MANTRA)."
            ),
        })
    return hits

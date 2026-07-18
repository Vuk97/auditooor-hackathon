"""
r94_loop_fee_harvest_swap_zero_min_out.py

Flags fee-harvest / sellProfits fns that perform an internal swap and
pass `0` as amount_out_minimum / min_out — harvest cycle sandwichable.

Source: Solodit #30948 (Beefy StrategyPassiveManagerUniswap).
Class: fee-harvest-swap-zero-min-out (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(r"(?i)(charge_fee|harvest|sell_profits|collect_fee|swap_fees|convert_fee)")
_SWAP_CALL_RE = re.compile(
    r"(\.swap\s*\(|\.exact_input\s*\(|\.exact_output\s*\(|uni_v3_swap\s*\(|"
    fr"swap_exact_tokens_for_tokens\s*\(|router\s*\.\s*{IDENT}swap)"
)
_ZERO_MIN_OUT_RE = re.compile(
    r"amount_out_minimum\s*:\s*0\b|min_out\s*:\s*0\b|"
    r"amountOutMin(imum)?\s*:\s*0\b|min_amount_out\s*:\s*0\b|"
    r",\s*0\s*,\s*0\s*\)"  # positional trailing (min, deadline) both zero
)
_NONZERO_MIN_OUT_RE = re.compile(
    r"amount_out_minimum\s*:\s*(?!0\b)[a-zA-Z_]\w*|"
    r"min_out\s*:\s*(?!0\b)[a-zA-Z_]\w*|"
    r"expected_out\s*[-*]\s*\w+"
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
        if not _SWAP_CALL_RE.search(body_nc):
            continue
        if not _ZERO_MIN_OUT_RE.search(body_nc):
            continue
        if _NONZERO_MIN_OUT_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` performs an internal fee swap with "
                f"amount_out_minimum = 0 — every harvest sandwichable "
                f"(fee-harvest-swap-zero-min-out). See Solodit #30948 "
                f"(Beefy)."
            ),
        })
    return hits

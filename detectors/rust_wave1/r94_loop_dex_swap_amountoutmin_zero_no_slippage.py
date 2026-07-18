"""
r94_loop_dex_swap_amountoutmin_zero_no_slippage.py

Flags DEX-wrapper fns that call a router swap (swapExactTokensForTokens,
exactInputSingle) with a hard-coded `amount_out_min = 0` literal —
sandwich MEV extracts full slippage.

Source: Solodit #51371 (Halborn Entangle Trillion DexWrappers).
Class: dex-swap-amountoutmin-zero-no-slippage (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(swap_exact|exact_input|exact_output|"
    r"swap_via_dex|swap_router|swap_tokens|"
    r"execute_swap|uniswap_swap|dex_swap)"
)
_HARDCODED_ZERO_RE = re.compile(
    r"(?i)(amount_out_min\s*:\s*0\b|"
    r"amountOutMin\s*:\s*0\b|"
    r"amountOutMinimum\s*:\s*0\b|"
    r"min_amount_out\s*:\s*0\b|"
    r"min_out\s*:\s*0\b|"
    r"\w*(swap|router|uniswap|dex)\w*\s*\(\s*[\w\s,\.]*,\s*0\s*,\s*\w*(path|fee|deadline)|"
    r"exact_input_single\s*\(\s*[^)]*,\s*0\s*,|"
    fr",\s*0\s*,\s*{IDENT}deadline\s*\))"
)
_USER_MIN_RE = re.compile(
    fr"(?i)(amount_out_min\s*:\s*{IDENT}min_out|"
    fr"amountOutMin\s*:\s*{IDENT}min|"
    fr"amountOutMinimum\s*:\s*{IDENT}min|"
    fr"min_amount_out\s*:\s*{IDENT}(out|expected)|"
    fr"user_min_out|caller_supplied_min|"
    fr"slippage_protect|check_slippage)"
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
        if not _HARDCODED_ZERO_RE.search(body_nc):
            continue
        if _USER_MIN_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` calls a DEX router with "
                f"`amount_out_min = 0` — sandwich MEV extracts full "
                f"slippage on every swap "
                f"(dex-swap-amountoutmin-zero-no-slippage). "
                f"See Solodit #51371 (Halborn Entangle Trillion)."
            ),
        })
    return hits

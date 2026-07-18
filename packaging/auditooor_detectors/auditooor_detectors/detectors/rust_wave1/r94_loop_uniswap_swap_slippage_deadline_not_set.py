"""
r94_loop_uniswap_swap_slippage_deadline_not_set.py

Flags fns that call Uniswap V2/V3 swap routers with both
`amountOutMinimum = 0` AND `deadline = type(uint256).max` —
sandwich MEV extracts full slippage and the tx can sit in
the mempool indefinitely.

Source: Solodit #19136 (Sherlock USSD - Autonomous Secure Dollar).
Class: uniswap-swap-slippage-deadline-not-set (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(
    r"(?i)(swap|rebalance|exact_input|execute_swap|"
    r"uniswap_swap|trade_via_uniswap|router_exact_input)"
)
_V3_SWAP_RE = re.compile(
    r"(?i)(swap_exact_tokens_for_tokens|swapExactTokensForTokens|"
    r"exact_input_single|exactInputSingle|ISwapRouter|"
    r"IUniswapV2Router\w*|router\s*\.\s*swap)"
)
_BAD_SLIPPAGE_RE = re.compile(
    r"(?i)(amount_out_min(?:imum)?\s*:\s*0\b|"
    r"amountOutMin(?:imum)?\s*:\s*0\b|"
    r",\s*0\s*,\s*type_::MAX|u256::MAX|u64::MAX|"
    r"uint256\(-1\)|type\(uint256\)\.max)"
)
_BAD_DEADLINE_RE = re.compile(
    r"(?i)(deadline\s*:\s*(u256::MAX|u64::MAX|"
    r"type\(uint256\)\.max|uint256_max|\w*::MAX)|"
    r"deadline\s*:\s*block\.timestamp\s*\+\s*\w*365)"
)
_SAFE_RE = re.compile(
    r"(?i)(user_min_out|slippageBps|"
    fr"min_amount_out\s*:\s*{IDENT}user|"
    fr"require\s*\(\s*{IDENT}received\s*>=|"
    r"caller_supplied_deadline|"
    r"deadline\s*:\s*\w*(user_|caller_)deadline)"
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
        if not _V3_SWAP_RE.search(body_nc):
            continue
        if not (_BAD_SLIPPAGE_RE.search(body_nc) or _BAD_DEADLINE_RE.search(body_nc)):
            continue
        if _SAFE_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` calls Uniswap V2/V3 swap with "
                f"amountOutMinimum = 0 AND deadline = type(uint256).max — "
                f"sandwich MEV extracts full value and tx can lie in the "
                f"mempool indefinitely "
                f"(uniswap-swap-slippage-deadline-not-set). "
                f"See Solodit #19136 (Sherlock USSD)."
            ),
        })
    return hits

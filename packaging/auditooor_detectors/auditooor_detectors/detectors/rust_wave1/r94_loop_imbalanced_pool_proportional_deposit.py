"""
r94_loop_imbalanced_pool_proportional_deposit.py

Flags deposit/restore fns that call a Curve/AMM `add_liquidity` /
`join_pool` with proportional amounts but no imbalance detection.

Source: Solodit #29096 (Sherlock Notional).
Class: imbalanced-pool-proportional-deposit (both).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)

_FN_NAME_RE = re.compile(r"(?i)(deposit|restore|reinvest|rebalance|top_up)")
_PROPORTIONAL_RE = re.compile(
    r"add_liquidity\s*\(|join_pool\s*\(|\.add_liquidity\s*\(|"
    r"proportional_deposit|two_token_pool"
)
_IMBALANCE_CHECK_RE = re.compile(
    r"is_imbalanced|detect_imbalance|balance_ratio|imbalance_threshold|"
    r"balances_equal|single_side_fallback|check_pool_balance"
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
        if not _PROPORTIONAL_RE.search(body_nc):
            continue
        if _IMBALANCE_CHECK_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "medium",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` performs a proportional Curve/AMM "
                f"deposit without first checking pool balance. Imbalanced "
                f"pool → sub-optimal LP-token return. See Solodit "
                f"#29096 (Notional)."
            ),
        })
    return hits

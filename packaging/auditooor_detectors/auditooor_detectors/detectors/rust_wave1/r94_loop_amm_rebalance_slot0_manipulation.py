"""
r94_loop_amm_rebalance_slot0_manipulation.py

Flags LP manager rebalance/reallocate fns that read
`slot0` / `current_tick` / `sqrt_price_x96` from the pool to decide
whether to act — slot0 is manipulable via flash swap within a block.

Source: Solodit #34883 (Predy LP reallocate).
Class: amm-rebalance-slot0-manipulation (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(reallocate|rebalance|shift_range|rotate_position|adjust_tick)")
_SLOT0_READ_RE = re.compile(
    r"\.slot0\s*\(|\.slot_0\s*\(|current_tick\s*\(|get_current_tick|"
    r"sqrt_price_x96|sqrtPriceX96|pool\s*\.\s*tick"
)
_TWAP_RE = re.compile(
    r"(observe|twap|twap_price|twap_tick|oracle_tick|get_tick_cumulatives|"
    r"observation\.tick_cumulative)"
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
        if not _SLOT0_READ_RE.search(body_nc):
            continue
        if _TWAP_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` reads slot0 / current_tick / "
                f"sqrtPriceX96 to decide rebalance — slot0 is "
                f"manipulable via flash swap, attacker forces bad "
                f"rebalance (amm-rebalance-slot0-manipulation). "
                f"See Solodit #34883 (Predy)."
            ),
        })
    return hits

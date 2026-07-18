"""
r94_loop_perp_open_price_rounds_down_drift.py

Flags perp position fill/update fns that compute a weighted-average
`open_price` using integer division that ROUNDS DOWN without a
ceil/mul_div-up safeguard — attacker drifts open_price downward
via crafted fills.

Source: Solodit #53997 (Cantina Layer N).
Class: perp-open-price-rounds-down-drift (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(fill|fill_order|update_position|merge_fill|apply_trade|execute_fill)")
_OPEN_PRICE_RE = re.compile(
    r"(open_price|avg_entry_price|weighted_price|entry_price)\s*=\s*\([^;]{0,200}\)\s*/\s*\w+",
    re.DOTALL,
)
_CEIL_RE = re.compile(
    r"mul_div_up|ceil_div|div_ceil|\.div_ceil|round_up|\.ceil\s*\(|"
    r"\(\s*\w+\s*\+\s*\w+\s*-\s*1\s*\)\s*/\s*\w+"
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
        if not _OPEN_PRICE_RE.search(body_nc):
            continue
        if _CEIL_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` computes weighted-average open_price "
                f"with integer / rounding-down division — attacker "
                f"drifts open_price lower via crafted fills "
                f"(perp-open-price-rounds-down-drift). See Solodit "
                f"#53997 (Layer N)."
            ),
        })
    return hits

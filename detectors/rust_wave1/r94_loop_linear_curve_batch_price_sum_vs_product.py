"""
r94_loop_linear_curve_batch_price_sum_vs_product.py

Flags linear-curve buy/sell pricing fns that compute batch total
as `price_n * n` instead of the arithmetic-series
`sum_{i=1..n} (base + delta*i)`.

Source: Solodit #48189 (OtterSec Stargaze Infinity).
Class: linear-curve-batch-price-sum-vs-product (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(r"(?i)(get_buy_price|get_sell_price|calc_batch_price|linear_price|compute_batch_cost)")
_LINEAR_MARKER_RE = re.compile(
    r"(Linear|linear_curve|\"linear\"|PricingCurve::Linear|CurveType::Linear|curve_type)"
)
_PRODUCT_FORM_RE = re.compile(
    fr"(price\s*\(\s*{IDENT}n\s*\)\s*\*\s*{IDENT}n|"
    fr"{IDENT}batch_price\s*=\s*{IDENT}unit_price\s*\*\s*\w+|"
    fr"return\s+{IDENT}price\s*\*\s*{IDENT}count)"
)
_SERIES_SUM_RE = re.compile(
    r"(arithmetic_series|sum_series|sum_range|"
    r"n\s*\*\s*\(\s*2\s*\*\s*base|"
    r"for\s+\w+\s+in\s+\w+\s*\.\.\w+\s*\{[\s\S]{0,200}?\+=)"
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
        if not _LINEAR_MARKER_RE.search(body_nc):
            continue
        if not _PRODUCT_FORM_RE.search(body_nc):
            continue
        if _SERIES_SUM_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` computes linear-curve batch price "
                f"as `price(n) * n` instead of arithmetic-series sum "
                f"— wrong for batches >1 (linear-curve-batch-price-"
                f"sum-vs-product). See Solodit #48189 (Stargaze)."
            ),
        })
    return hits

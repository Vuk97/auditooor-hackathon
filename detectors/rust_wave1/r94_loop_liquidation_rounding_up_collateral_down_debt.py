"""
r94_loop_liquidation_rounding_up_collateral_down_debt.py

Flags liquidate fns that round UP the seized-collateral amount (or
use ceil_div) while debt repayment uses floor division — repeated
calls drain the position.

Source: Solodit #48868 (OtterSec Port Finance).
Class: liquidation-rounding-up-collateral-down-debt (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(liquidate|seize_collateral|liquidate_position|liquidate_sundial)")
_COLLATERAL_CEIL_RE = re.compile(
    r"(collateral|seized|seize_amount|liquidator_amount)\s*=\s*\w*(ceil_div|mul_div_up|round_up|ceiling|\.div_ceil)|"
    r"(ceil_div|mul_div_up|round_up|div_ceil)\s*\([^;]{0,200}(collateral|seize)",
    re.DOTALL,
)
_DEBT_FLOOR_RE = re.compile(
    r"(debt_repaid|repay_amount|principal_paid)\s*=\s*\w+\s*\*\s*\w+\s*/\s*\w+|"
    r"(debt_amount|repay)\s*\.\s*floor\s*\(|"
    r"repay\s*=\s*\w+\s*/\s*\w+"
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
        if not _COLLATERAL_CEIL_RE.search(body_nc):
            continue
        if not _DEBT_FLOOR_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` rounds UP collateral seized while "
                f"debt repayment uses floor — repeated calls drain "
                f"the position (liquidation-rounding-up-collateral-"
                f"down-debt). See Solodit #48868 (Port Finance)."
            ),
        })
    return hits

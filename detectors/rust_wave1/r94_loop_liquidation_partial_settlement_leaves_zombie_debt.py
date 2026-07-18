"""
r94_loop_liquidation_partial_settlement_leaves_zombie_debt.py

Flags liquidation fns that reduce `debt` by a partial amount
(e.g., `pool_available`, `min(debt, pool)`) but never explicitly
zero the borrower's debt when collateral is seized. If the
stability pool / available amount is less than the debt, the
borrower retains zombie debt while their collateral is taken.

Source: Solodit #57323 (Codehawks RAAC StabilityPool).
Class: liquidation-partial-settlement-leaves-zombie-debt (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(liquidate|liquidate_borrower|liquidate_position|"
    r"liquidate_trove|liquidate_with_pool|"
    r"close_position_by_liquidation|seize_and_repay)"
)
# Partial debt reduction based on pool / min(debt, pool).
_PARTIAL_RE = re.compile(
    fr"(?i)(debt\s*-=\s*{IDENT}(pool|available|sp_deposits)|"
    fr"borrower\.debt\s*=\s*borrower\.debt\s*-\s*{IDENT}(pool|available)|"
    fr"{IDENT}repayable\s*=\s*{IDENT}min\s*\(\s*{IDENT}debt\s*,|"
    fr"{IDENT}min\s*\(\s*{IDENT}debt\s*,\s*{IDENT}(pool_available|stability_pool)|"
    fr"debt\s*=\s*debt\.saturating_sub\s*\(\s*{IDENT}(pool|deposits))"
)
# Safe: zero debt / close position if pool insufficient, OR revert.
_ZERO_OR_REVERT_RE = re.compile(
    fr"(?i)(borrower\.debt\s*=\s*0|"
    fr"debt\s*=\s*0\s*;|"
    fr"require\s*\(\s*{IDENT}pool_available\s*>=\s*{IDENT}debt|"
    fr"revert\s*{IDENT}InsufficientStabilityPool|"
    fr"panic\s*!\s*\(\s*\"(pool|insufficient)|"
    fr"position\.debt\s*=\s*0\s*;|"
    fr"clear_debt\s*\(|zero_debt\s*\()"
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
        if not _PARTIAL_RE.search(body_nc):
            continue
        if _ZERO_OR_REVERT_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` reduces debt by the stability-pool "
                f"available amount (partial settlement) without "
                f"zeroing borrower.debt or reverting when the pool "
                f"is insufficient — borrower keeps zombie debt while "
                f"collateral is seized "
                f"(liquidation-partial-settlement-leaves-zombie-debt). "
                f"See Solodit #57323 (Codehawks RAAC StabilityPool)."
            ),
        })
    return hits

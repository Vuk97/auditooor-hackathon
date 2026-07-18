"""
r94_loop_liquidation_bonus_strict_reverts_when_underfunded.py

Flags liquidate fns that compute `required = debt + bonus` and assert
it is <= deposited collateral as a hard gate — when collateral drops
below the bonus threshold, liquidation reverts and bad debt
accumulates.

Source: Solodit #34420 (Foundry DeFi Stablecoin).
Class: liquidation-bonus-strict-reverts-when-underfunded (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(r"(?i)(liquidate|seize_collateral|liquidate_position)")
_BONUS_ADD_RE = re.compile(
    r"(debt|repay_amount|amount_to_cover)\s*\*\s*\(\s*(100|\s*1e\d+)\s*\+\s*(bonus|liquidation_bonus|liq_bonus)|"
    r"debt\s*\+\s*\w+\s*\*\s*(bonus|liquidation_bonus|liq_bonus)|"
    r"\b(liquidation_bonus|liq_bonus)\s*\*\s*debt"
)
_STRICT_REVERT_RE = re.compile(
    fr"require\s*\(\s*{IDENT}(required|total_seize|bonus_seize|collateral_seize)\s*<=\s*{IDENT}collateral|"
    fr"assert[!_]?\s*\(\s*{IDENT}(required|total_seize)\s*<=\s*{IDENT}collateral|"
    fr"if\s+{IDENT}collateral\s*<\s*{IDENT}(required|total_seize)\s*\{{\s*panic|"
    fr"ensure\s*!\s*\(\s*{IDENT}collateral\s*>=\s*{IDENT}(required|total_seize)"
)
_CAP_CLAMP_RE = re.compile(
    fr"min\s*\(\s*{IDENT}(required|bonus_seize)\s*,\s*{IDENT}collateral|"
    fr"math::min\s*\(|cap_at\s*\(|clamp_to_collateral"
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
        if not _BONUS_ADD_RE.search(body_nc):
            continue
        if not _STRICT_REVERT_RE.search(body_nc):
            continue
        if _CAP_CLAMP_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` strict-requires `required (debt + "
                f"bonus) <= collateral` — when collateral drops below "
                f"bonus threshold liquidation reverts and bad debt "
                f"accumulates (liquidation-bonus-strict-reverts-when-"
                f"underfunded). See Solodit #34420 (Foundry DeFi)."
            ),
        })
    return hits

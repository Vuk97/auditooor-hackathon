"""
r94_loop_cdp_borrow_repay_cycle_rate_inflate_grief.py

Flags CDPVault / lending pool borrow / repay fns that recompute
`utilization_rate = borrowed / supplied` and `apply_rate_factor`
each call without a per-block / per-user smoothing — attacker
cycles tiny borrow-then-repay actions to inflate the accumulated
rate for every other borrower.

Source: Solodit #49029 (Code4rena LoopFi CDPVault).
Class: cdp-borrow-repay-cycle-rate-inflate-grief (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(\bborrow\b|\brepay\b|borrow_with_collateral|"
    r"repay_with_collateral|increase_debt|decrease_debt|"
    r"borrow_amount|repay_amount|modify_position)"
)
# Recomputes util / rate factor in-line.
_RATE_UPDATE_RE = re.compile(
    r"(?i)(utilization_rate\s*=|utilizationRate\s*=|"
    r"update_rate\s*\(|updateRate\s*\(|"
    r"accrue_interest\s*\(|accrueInterest\s*\(|"
    r"rate_factor\s*=|rateFactor\s*=|"
    r"virtual_price\s*=|interest_index\s*=)"
)
# Safe: minimum amount check or per-block caching.
_SMOOTH_RE = re.compile(
    fr"(?i)(min_borrow_amount|minBorrowAmount|"
    fr"min_repay_amount|minRepayAmount|"
    fr"require\s*\(\s*{IDENT}amount\s*>=\s*{IDENT}MIN_|"
    fr"last_rate_update_block|lastRateUpdateBlock|"
    fr"if\s+{IDENT}block\s*\.\s*number\s*==\s*{IDENT}last_update|"
    fr"rate_update_cooldown|rateUpdateCooldown|"
    fr"skip_rate_update_for_self|"
    fr"{IDENT}min_debt_delta|dust_floor)"
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
        if not _RATE_UPDATE_RE.search(body_nc):
            continue
        if _SMOOTH_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` recomputes utilization / rate "
                f"factor on every call with no per-block cache, "
                f"min-amount floor, or cooldown — attacker cycles "
                f"tiny borrow-then-repay actions to inflate the "
                f"accumulated rate for other borrowers "
                f"(cdp-borrow-repay-cycle-rate-inflate-grief). "
                f"See Solodit #49029 (Code4rena LoopFi CDPVault)."
            ),
        })
    return hits

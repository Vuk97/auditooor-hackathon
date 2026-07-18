"""
r94_loop_lp_token_claim_redemption_ratio_spot_reserves_manipulable.py

Flags LP-claim / liquidity-value fns that compute per-LP claim as
`lpAmount * reserve / totalSupply` using *current* pool reserves
and totalSupply. Attacker flashloans, inflates a reserve,
computes the claim at favourable ratio, borrows above collateral.

Source: Solodit #25545 (Code4rena Notional AssetHandler).
Class: lp-token-claim-redemption-ratio-spot-reserves-manipulable (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(get_liquidity_token_value|get_cash_claims|"
    r"get_claims|redeem_shares|compute_redemption|"
    r"cash_claim_for_lp|lp_claim|fcash_claim|"
    r"get_haircut_cash_claims)"
)
# Computes lpAmount * reserve / totalSupply form.
_CLAIM_RATIO_RE = re.compile(
    fr"(?i)(lp_amount\s*\*\s*{IDENT}(reserve|balance|assetCash)\s*\/\s*{IDENT}total_supply|"
    fr"lpAmount\s*\*\s*{IDENT}(reserve|balance)\s*\/\s*{IDENT}totalSupply|"
    fr"{IDENT}lp_shares\s*\*\s*{IDENT}reserve\s*\/\s*{IDENT}total_supply|"
    fr"{IDENT}amount\s*\*\s*{IDENT}pool_balance\s*\/\s*{IDENT}total_supply|"
    fr"{IDENT}shares\s*\*\s*{IDENT}reserves\s*\[\s*\w+\s*\]\s*\/\s*{IDENT}total_supply)"
)
# Safe: uses stored / snapshot reserves, or TWAP-averaged supply.
_SNAPSHOT_RE = re.compile(
    fr"(?i)(snapshot{IDENT}reserve|stored_reserve|"
    r"cached_reserve|checkpoint_reserves|"
    r"oracle_reserves|twap_reserves|"
    r"reserve_at_block\s*\(|reserveAtBlock|"
    r"historical_total_supply|past_total_supply)"
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
        if not _CLAIM_RATIO_RE.search(body_nc):
            continue
        if _SNAPSHOT_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` computes the LP claim as "
                f"`lp_amount * reserve / total_supply` from current "
                f"pool state — attacker flashloans, inflates a "
                f"reserve, computes the claim at a favourable ratio "
                f"and borrows above collateral "
                f"(lp-token-claim-redemption-ratio-spot-reserves-manipulable). "
                f"See Solodit #25545 (Code4rena Notional AssetHandler)."
            ),
        })
    return hits

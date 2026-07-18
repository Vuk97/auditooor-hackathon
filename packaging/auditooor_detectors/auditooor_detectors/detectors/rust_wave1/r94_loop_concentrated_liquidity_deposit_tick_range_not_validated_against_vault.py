"""
r94_loop_concentrated_liquidity_deposit_tick_range_not_validated_against_vault.py

Flags deposit/mint-position fns that accept caller-supplied
`tick_lower` / `tick_upper` and forward them to a Pool call or
storage write without asserting the ticks fall within the vault's
configured concentration range — attacker opens positions outside
the premium zone, diluting LPs.

Source: Solodit #65235 (Pashov Audit Group Saffron Vaults).
Class: concentrated-liquidity-deposit-tick-range-not-validated-against-vault (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(deposit_fixed|deposit_range|add_liquidity_range|"
    r"mint_position|provide_range_liquidity|deposit_concentrated)"
)
_TAKES_USER_TICKS_RE = re.compile(
    r"(tick_lower|tickLower)[\s\S]{0,80}?(tick_upper|tickUpper)"
)
_SAFE_BOUND_CHECK_RE = re.compile(
    fr"vault\s*\.\s*tick_lower|"
    fr"vault_tick_lower|"
    fr"tick_lower\s*>=\s*{IDENT}vault\.tick_lower|"
    fr"tick_upper\s*<=\s*{IDENT}vault\.tick_upper|"
    fr"assert\w*\s*!?\s*\(\s*{IDENT}tick_lower\s*>=\s*{IDENT}vault|"
    fr"require\s*\(\s*{IDENT}tickLower\s*>=\s*{IDENT}vault\.tickLower|"
    fr"align_to_vault_tick_range|"
    fr"within_vault_range"
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
        if not _TAKES_USER_TICKS_RE.search(body_nc):
            continue
        if _SAFE_BOUND_CHECK_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn {name} accepts caller-supplied "
                f"tick_lower/tick_upper without asserting they fall "
                f"within the vault's concentration range — attacker "
                f"opens positions outside the premium zone "
                f"(concentrated-liquidity-deposit-tick-range-not-validated-against-vault). "
                f"See Solodit #65235 (Pashov Audit Group Saffron Vaults)."
            ),
        })
    return hits

"""
r94_loop_deposit_tick_range_not_validated_against_vault.py

Flags deposit_fixed / deposit_liquidity fns that accept user
`tick_lower` and `tick_upper` params WITHOUT validating they match
the vault's configured range (vault.tick_lower / vault.tick_upper).

Source: Solodit #65235 (Saffron concentrated-liquidity vault).
Class: deposit-tick-range-not-validated-against-vault (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(r"(?i)(deposit_fixed|deposit_liquidity|add_liquidity_fixed|provide_lp)")
_USER_TICK_ARG_RE = re.compile(
    r"fn\s+\w+\s*\([^)]*\btick_lower\s*:[\s\S]{0,200}?tick_upper\s*:"
)
_VALIDATION_RE = re.compile(
    fr"(tick_lower\s*==\s*{IDENT}vault\.tick_lower|"
    fr"tick_upper\s*==\s*{IDENT}vault\.tick_upper|"
    fr"require\s*\(\s*tick_lower\s*==\s*{IDENT}vault|"
    fr"assert[!_]?eq\s*\(\s*tick_lower\s*,\s*{IDENT}vault\.tick_lower)"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        sig_text = snippet_of(fn, source)
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        if not _USER_TICK_ARG_RE.search(sig_text):
            continue
        if _VALIDATION_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": sig_text[:200],
            "message": (
                f"pub fn `{name}` takes user tick_lower/tick_upper "
                f"but doesn't validate they match vault's configured "
                f"range — depositor places LP outside vault range, "
                f"skips premium (deposit-tick-range-not-validated-"
                f"against-vault). See Solodit #65235 (Saffron)."
            ),
        })
    return hits

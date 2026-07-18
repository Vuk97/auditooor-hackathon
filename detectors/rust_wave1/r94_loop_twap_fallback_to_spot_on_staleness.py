"""
r94_loop_twap_fallback_to_spot_on_staleness.py

Flags oracle fns that read a TWAP / averaged price but fall back to
spot / last_px / current_price on staleness — attacker manipulates
spot then forces TWAP staleness to trigger the fallback.

Source: Solodit #31108 (C4 Salty.IO CoreSaltyFeed).
Class: twap-fallback-to-spot-on-staleness (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(get_price|fetch_price|price_of|oracle_price|get_token_price)")
_TWAP_AND_FALLBACK_RE = re.compile(
    r"(twap|time_weighted|moving_average)[\s\S]{0,400}?"
    r"(if\s+\w*(ts|timestamp|stale|update|now|last)[\s\S]{0,80}?\{|"
    r"else\s*\{)[\s\S]{0,200}?"
    r"(spot_price|last_px|current_price|live_price|pool\.reserves|reserve0\s*,\s*reserve1)",
    re.DOTALL | re.IGNORECASE,
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
        if not _TWAP_AND_FALLBACK_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` returns TWAP primary but falls back "
                f"to spot/last_px on staleness — attacker manipulates "
                f"spot and forces staleness to poison pricing "
                f"(twap-fallback-to-spot-on-staleness). See Solodit "
                f"#31108 (Salty.IO)."
            ),
        })
    return hits

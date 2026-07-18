"""
r94_loop_pmm_internal_price_manipulation.py

Flags fns that compute PMM / internal-oracle price from on-pool reserves
(base_balance / quote_balance) without sanity-check vs external oracle.

Source: Solodit #31886 (WOOFi).
Class: pmm-internal-price-manipulation (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(query|get_price|pmm_price|quote_price|internal_price)")
_PMM_CTX_RE = re.compile(r"base_balance|quote_balance|pmm_state|reserve0\s*/\s*reserve1")
_EXT_ORACLE_RE = re.compile(r"chainlink|external_oracle|oracle_ref|pyth|sanity_price")


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
        if not _PMM_CTX_RE.search(body_nc):
            continue
        if _EXT_ORACLE_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` derives internal/PMM price from pool "
                f"reserves (base_balance / quote_balance) without cross-"
                f"check vs external oracle. Flash-skewed reserve → bad "
                f"price. See Solodit #31886 (WOOFi)."
            ),
        })
    return hits

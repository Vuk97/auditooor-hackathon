"""
r94_loop_cross_timestamp_source_drift.py

Flags fns that compare a 3rd-party-oracle timestamp (Pyth publish_time)
against a local chain timestamp with a signed subtraction (u64 - u64
or block_timestamp - publish_time) without a max(, 0) floor or a
sign-aware diff.

Source: Solodit #46890 (OtterSec Fluid Protocol Fuel).
Class: cross-timestamp-source-drift (both).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment, IDENT, CALL,
)

_FN_NAME_RE = re.compile(r"(?i)(get_price|check_staleness|validate_pyth|price_freshness|get_latest_price)")
_SUBTRACT_RE = re.compile(
    fr"timestamp\s*\(\s*\)\s*-\s*\w+\.(publish_time|price\.timestamp|oracle_ts)|"
    fr"(publish_time|price\.timestamp|oracle_ts)\s*-\s*{IDENT}timestamp\s*\(\s*\)|"
    fr"(\bnow\b|\bblock_timestamp\b)\s*-\s*\w+\.(publish_time|oracle_ts)"
)
_SAFE_DIFF_RE = re.compile(
    r"saturating_sub|checked_sub|abs_diff|\.abs\s*\(|max\s*\(\s*\w+\s*-\s*\w+\s*,\s*0\s*\)|"
    r"if\s+\w+\s*<\s*\w+\s*\{\s*0\s*\}\s*else|"
    r"if\s+\w+\s*>=\s*\w+"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    root = tree.root_node
    for fn, _impl in functions_in_contractimpl(root, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        if not _SUBTRACT_RE.search(body_nc):
            continue
        if _SAFE_DIFF_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "medium",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` subtracts oracle publish_time from local "
                f"chain timestamp (or vice versa) without saturating_sub / "
                f"abs_diff / signed check. Cross-source drift produces "
                f"underflow / wrong staleness verdict. See Solodit #46890 "
                f"(Fluid Protocol Fuel)."
            ),
        })
    return hits

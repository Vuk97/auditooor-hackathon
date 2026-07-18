"""
r94_loop_unsafe_cast_uint256_to_uint128_no_safecast.py

Flags direct casts from u256 → u128 (or uint256 → uint128 in Sol)
without SafeCast / checked conversion — silent truncation when
source exceeds 2^128-1.

Source: Solodit #59252 (Quantstamp Sperax Farms).
Class: unsafe-cast-uint256-to-uint128-no-safecast (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(update_\w+|accrue\w*|record_\w*|settle_\w*|apply_\w*|convert_\w*|deposit|withdraw)")
_UNSAFE_CAST_RE = re.compile(
    r"\bas\s+u128\b|"
    r"uint128\s*\(\s*\w*(amount|balance|total|supply|reserve|shares|principal|debt)"
)
_SAFE_CAST_RE = re.compile(
    r"SafeCast::to_u128|SafeCast\.toUint128|toU128\s*\(|to_u128_checked|"
    r"try_into\s*\(\s*\)\s*\.\s*unwrap|u128::try_from"
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
        if not _UNSAFE_CAST_RE.search(body_nc):
            continue
        if _SAFE_CAST_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` casts u256/uint256 to u128 via "
                f"direct `as u128` / `uint128(...)` without SafeCast "
                f"— silent truncation on large values (unsafe-cast-"
                f"uint256-to-uint128-no-safecast). See Solodit "
                f"#59252 (Sperax Farms)."
            ),
        })
    return hits

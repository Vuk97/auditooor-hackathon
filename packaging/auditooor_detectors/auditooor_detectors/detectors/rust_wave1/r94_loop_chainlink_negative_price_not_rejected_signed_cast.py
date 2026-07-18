"""
r94_loop_chainlink_negative_price_not_rejected_signed_cast.py

Flags price-feed fns that cast a signed Chainlink answer (i256 /
int256) to an unsigned type or compare it to an unsigned
threshold without first asserting the answer is strictly
positive. Chainlink can report a negative answer during severe
price events — a negative int cast to uint wraps to a huge
number.

Source: Solodit #59820 (Quantstamp Sperax USDs).
Class: chainlink-negative-price-not-rejected-signed-cast (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(current_price|get_price|price_of|"
    r"fetch_price|compute_price|query_price|"
    r"latest_price|usd_price|get_asset_price)"
)
# Cast of int256 / i256 answer to unsigned.
_SIGNED_CAST_RE = re.compile(
    fr"(?i)(uint256\s*\(\s*{IDENT}answer|"
    fr"u256::from\s*\(\s*{IDENT}answer|"
    fr"\bas\s+u256\s*|"
    fr"\bas\s+u128\s*|"
    fr"\bas\s+u64\s*|"
    fr"answer\s*\.\s*unsigned_abs|"
    fr"answer\s*\.\s*abs\s*\(\s*\)|"
    fr"int256\s*\(\s*{IDENT}answer\s*\)\s*\.\s*to_uint|"
    fr"\bi256\s*->\s*u256)"
)
# Safe: explicit positive check.
_POSITIVE_CHECK_RE = re.compile(
    fr"(?i)(require\s*\(\s*{IDENT}answer\s*>\s*0|"
    fr"assert\w*\s*!?\s*\(\s*{IDENT}answer\s*>\s*0|"
    fr"answer\s*>\s*0\s*,|"
    fr"answer\s*>=\s*0\s*,|"
    fr"if\s+{IDENT}answer\s*<=?\s*0\s*\{{\s*(revert|panic|return)|"
    fr"answer\s*\.\s*is_positive|"
    fr"\bi256\s*::\s*ZERO\s*<\s*{IDENT}answer)"
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
        # Must use latestRoundData / latestAnswer.
        if not re.search(r"(?i)(latest_round_data|latestRoundData|latest_answer|latestAnswer)", body_nc):
            continue
        if not _SIGNED_CAST_RE.search(body_nc):
            continue
        if _POSITIVE_CHECK_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` casts a signed Chainlink `answer` "
                f"to unsigned without a `require(answer > 0)` — a "
                f"negative feed reading wraps to a huge uint and "
                f"poisons pricing "
                f"(chainlink-negative-price-not-rejected-signed-cast). "
                f"See Solodit #59820 (Quantstamp Sperax USDs)."
            ),
        })
    return hits

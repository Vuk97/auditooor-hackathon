"""
r94_loop_curve_remove_liquidity_zero_min.py

Flags controller fns interpreting Curve `remove_liquidity` semantics
that filter tokens by `min_amount > 0` when building a token-in list
— Curve returns ALL underlying tokens regardless of min_amount.

Source: Solodit #3355 (Sherlock Sentiment).
Class: curve-remove-liquidity-zero-min (both).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)

_FN_NAME_RE = re.compile(r"(?i)(canRemove|can_remove_liquidity|on_remove_liquidity|track_removed|build_tokens_in)")

_CURVE_CTX_RE = re.compile(r"curve|StableSwap|remove_liquidity|tokensIn|tokens_in")

_FILTER_RE = re.compile(
    r"if\s+min_amounts?\s*\[[^\]]+\]\s*>\s*0|"
    r"\.filter\s*\(\s*\|.*min_amount\s*>\s*0|"
    r"min_amounts?\s*\[[^\]]+\]\s*>\s*0\s*\)\s*\.then"
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
        if not _CURVE_CTX_RE.search(body_nc):
            continue
        if not _FILTER_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` builds a tokens-in list for Curve "
                f"remove_liquidity and filters by `min_amounts[i] > 0`. "
                f"Curve returns ALL underlyings regardless — tokens with "
                f"min=0 are dropped from account tracker. See Solodit "
                f"#3355 (Sentiment)."
            ),
        })
    return hits

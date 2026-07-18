"""
r94_loop_chainlink_feed_decimals_hardcoded.py

Flags fns that scale a Chainlink price using a hardcoded decimal
constant (1e8 / 10**8 / 100_000_000) instead of calling
`pricefeed.decimals()`.

Source: Solodit #5773 (Code4rena Y2k Finance).
Class: chainlink-feed-decimals-hardcoded (both).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)

_FN_NAME_RE = re.compile(r"(?i)(get_price|price_of|scale_price|normalize_price|convert_price)")
_CHAINLINK_CTX_RE = re.compile(r"chainlink|latestRoundData|latest_round_data|AggregatorV3Interface|IAggregator")
_HARDCODED_SCALE_RE = re.compile(
    r"1e8\b|1_?00_?000_?000|10\s*\*\*\s*8|10u128\.pow\s*\(\s*8\s*\)|"
    r"decimals\s*:\s*(8|18)(?!\s*\.decimals)"
)
_DYNAMIC_DECIMALS_RE = re.compile(
    r"\.decimals\s*\(\s*\)|price_feed\.decimals|feed\.decimals"
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
        if not _CHAINLINK_CTX_RE.search(body_nc):
            continue
        if not _HARDCODED_SCALE_RE.search(body_nc):
            continue
        if _DYNAMIC_DECIMALS_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "medium",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` scales a Chainlink price with a "
                f"hardcoded decimal constant (1e8 / 10**8) instead of "
                f"calling `pricefeed.decimals()`. Feeds with non-default "
                f"decimals produce off-by-10^N prices. See Solodit #5773 "
                f"(Y2k Finance)."
            ),
        })
    return hits

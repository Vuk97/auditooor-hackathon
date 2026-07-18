"""
r94_loop_chainlink_feed_updatedat_not_checked.py

Flags price-feed fns that call `latest_round_data` (or Chainlink-
equivalent helpers) and use the returned answer without first
validating `updated_at` is within a staleness window. Stale /
frozen feed values get silently consumed.

Source: Solodit #2957 (Code4rena Juicebox JBChainlinkV3PriceFeed).
Class: chainlink-feed-updatedat-not-checked (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(current_price|get_price|price_of|"
    r"fetch_price|compute_price|query_price|"
    r"latest_price|usd_price|get_asset_price)"
)
_LATEST_CALL_RE = re.compile(
    r"(?i)(latest_round_data|latestRoundData|"
    r"latest_answer|latestAnswer|"
    r"aggregator\.\s*latest)"
)
# Safe: checks updated_at against a staleness window.
_STALENESS_RE = re.compile(
    fr"(?i)(updated_at\s*[<>]|updatedAt\s*[<>]|"
    fr"block\.timestamp\s*-\s*updated_at|"
    fr"block\.timestamp\s*-\s*updatedAt|"
    fr"block_timestamp\s*-\s*{IDENT}updated_at|"
    fr"require\s*\(\s*{IDENT}(block\.timestamp|env\.ledger\(\)\.timestamp)\s*-\s*{IDENT}updated_at\s*(<|<=)|"
    fr"assert\w*\s*!?\s*\(\s*{IDENT}updated_at\s*\+\s*{IDENT}(heartbeat|staleness|grace_period)|"
    fr"staleness_window|STALENESS_WINDOW|HEARTBEAT|"
    fr"max_stale_duration)"
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
        if not _LATEST_CALL_RE.search(body_nc):
            continue
        if _STALENESS_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` consumes a Chainlink "
                f"`latest_round_data` / `latest_answer` without "
                f"validating `updated_at` against a staleness "
                f"window — frozen / stale feed values are used as "
                f"current price "
                f"(chainlink-feed-updatedat-not-checked). "
                f"See Solodit #2957 (Code4rena Juicebox V2)."
            ),
        })
    return hits

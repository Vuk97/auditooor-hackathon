"""
r94_loop_oracle_feed_id_mismatch.py

Flags fns that read a price from a feed-id (Pyth, Chainlink, Switchboard)
parameter without asserting the feed-id matches the configured asset mint /
symbol.

Source: common pattern across cross-chain oracle integrations.
Class: oracle-feed-id-mismatch (both).

Heuristic:
  1. Body calls a price-fetch method: `.get_price`, `pyth::get_price_feed`,
     `.get_latest_price`, `.price_of_feed`.
  2. The fetch takes a user/caller-supplied feed-id (`feed_id` param,
     `price_id`, `feed_pubkey`).
  3. Body does NOT contain an equality guard between the feed-id and the
     expected/configured one.
"""

from __future__ import annotations

import re

from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)


_PRICE_FETCH_RE = re.compile(
    r"\.get_price\s*\(|\.get_latest_price\s*\(|pyth::get_price_feed|"
    r"\.price_of_feed\s*\(|\.price_of\s*\(|\.latest_price\s*\(|"
    r"reflector::get_price\s*\(|\.price_feed\s*\(\s*&?feed|"
    r"load_price_feed_from_account(?:_info)?\s*\(|"
    r"price_feed_from_account(?:_info)?\s*\(|"
    r"\.get_price_unchecked\s*\(|\.get_price_no_older_than\s*\(|"
    r"\.get_current_price\s*\("
)

_FEED_ID_PARAM_RE = re.compile(
    r"\bfeed_id\b|\bprice_id\b|\bfeed_pubkey\b|\bfeed_account\b|"
    r"\boracle_account\b|\bprice_feed_account\b|"
    r"\bfeed_account_info\b|\boracle_pubkey\b"
)

_VALIDATION_RE = re.compile(
    r"feed_id\s*==\s*\w|price_id\s*==\s*\w|"
    r"\w+\s*==\s*feed_id|\w+\s*==\s*price_id|"
    r"require!?\s*\([^)]*(feed_id|price_id|feed_pubkey|oracle_account)[^)]*==|"
    r"require!?\s*\([^)]*==[^)]*(feed_id|price_id|feed_pubkey|oracle_account)|"
    r"assert_eq!?\s*\([^)]*(feed_id|price_id|feed_pubkey|oracle_account)|"
    r"whitelist_feeds\s*\.\s*contains\s*\([^)]*(feed_id|price_id|feed_pubkey)|"
    r"(price_feed|feed|pf)\s*\.\s*(id|feed_id|price_id)\s*==|"
    r"==\s*(price_feed|feed|pf)\s*\.\s*(id|feed_id|price_id)|"
    r"assert_eq!?\s*\([^)]*(price_feed|feed|pf)\s*\.\s*(id|feed_id|price_id)|"
    r"\.get_price_identifier\s*\(\s*\)\s*==|"
    r"==\s*\w+\.get_price_identifier\s*\(|"
    r"\.feed_id\s*==\s*\w+\.(feed_id|id)"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    root = tree.root_node
    for fn, _impl in functions_in_contractimpl(root, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)

        if not _PRICE_FETCH_RE.search(body_nc):
            continue
        if not _FEED_ID_PARAM_RE.search(body_nc):
            continue
        if _VALIDATION_RE.search(body_nc):
            continue

        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` fetches an oracle price using a caller-"
                f"supplied feed-id/price-id without asserting it matches "
                f"the configured asset's feed-id. Attacker can supply a "
                f"different asset's feed to mis-price."
            ),
        })
    return hits

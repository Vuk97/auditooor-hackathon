"""
price_feed_used_without_freshness_check.py

Narrower variant of the existing circuit-breaker detector — specifically
targets Reflector/Pyth price reads whose return contains a `timestamp` /
`publish_time` field that is NOT compared against `env.ledger().timestamp()`.

Heuristic:
  1. fn body calls `.lastprice(...)` / `.price(...)` / `.get_price(...)`
     / `.twap(...)` (Reflector API) and stores into a variable.
  2. Body does NOT compare that variable's `.timestamp` (or call
     `env.ledger().timestamp()` near the usage).

False positives avoided by:
  - Skipping fns whose names start with `set_`, `admin_`, `upgrade_`,
    `initialize`, `update_reflector`.
  - Skipping if the body text contains `MAX_AGE`, `max_staleness`,
    `stale_seconds`, `freshness`, `heartbeat`, `staleness` anywhere.
"""

from __future__ import annotations

import re

from _util import (
    function_items, fn_body, fn_name, text_of, walk_no_nested_fn,
    line_col, snippet_of, in_test_cfg,
)


_PRICE_CALLS = (
    r"\.lastprice\s*\(",
    r"\.twap\s*\(",
    r"\.price\s*\(",
    r"\.get_price\s*\(",
    r"\.price_unsafe\s*\(",
)

_FRESHNESS_TOKENS = (
    "MAX_AGE", "max_staleness", "stale_seconds", "freshness",
    "heartbeat", "staleness", "max_age", "validate_price_staleness",
    "check_staleness", "validate_price_freshness",
)

_ADMIN_PREFIXES = ("set_", "admin_", "upgrade_", "initialize", "init",
                   "update_reflector", "reset_", "remove_", "pause",
                   "unpause", "propose_", "accept_", "cancel_")


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        name = fn_name(fn, source)
        if any(name.startswith(p) for p in _ADMIN_PREFIXES):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_text = text_of(body, source)
        if not any(re.search(p, body_text) for p in _PRICE_CALLS):
            continue
        if any(t in body_text for t in _FRESHNESS_TOKENS):
            continue
        # If the body compares against ledger().timestamp(), treat as
        # freshness check.
        if re.search(
            r"ledger\s*\(\s*\)\s*\.\s*timestamp\s*\(\s*\)",
            body_text
        ):
            continue

        # Locate the price call
        node = None
        for n in walk_no_nested_fn(body):
            if n.type != "call_expression":
                continue
            t = text_of(n, source)
            if any(re.search(p, t) for p in _PRICE_CALLS):
                node = n
                break
        if node is None:
            continue
        line, col = line_col(node)
        hits.append({
            "severity": "med",
            "line": line,
            "col": col,
            "snippet": snippet_of(node, source),
            "message": (
                f"fn `{name}` consumes a Reflector/price-oracle read "
                f"without any freshness/staleness/heartbeat guard — "
                f"stale price can be used for pricing decisions."
            ),
        })
    return hits

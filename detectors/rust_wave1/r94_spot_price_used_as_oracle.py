"""
r94_spot_price_used_as_oracle.py

Flags fns that derive a price from a live pool's reserves or spot-slot0
and feed that number into a pricing / solvency / LTV / mint decision
without any TWAP accumulator or deviation-band check.  Flash-loan-fuelled
attacker can skew the pool, mint a lot of something cheap, and drain.

Maps to Solidity:
  - uniswap-v3-slot0-spot-price
  - ec-spot-price-used-as-oracle
  - lp-virtual-price-used-as-oracle
  - glider-curve-get-p-spot-price-oracle
  - pmm-quote-reads-external-oracle-without-deviation-band-vs-reserves
  - yield-protocol-balance-of-self-used-instead-of-cached

Heuristic:
  - Body reads pool reserves / spot slot: matches `get_reserves`,
    `reserves()`, `slot0`, `get_pool_balance`, `get_p`, `virtual_price`,
    or `balance_of` on the pool itself (`balance_of(pool_addr)`).
  - Body uses the result to compute a ratio (`/` or `*` with the read
    value) or passes it into a `mint`/`borrow`/`collateral`/`price`
    consumer.
  - Body has NO `twap`, `time_weighted`, `accumulator`, `cumulative`,
    `observe`, `deviation`, `median` guard.
"""

from __future__ import annotations

import re

from _util import (
    function_items, fn_body, fn_name, text_of, walk_no_nested_fn,
    line_col, snippet_of, in_test_cfg,
)


_RESERVE_RE = re.compile(
    r"\.get_reserves\s*\(|\.reserves\s*\(|\.slot0\s*\(|"
    r"\.get_pool_balance\s*\(|\.virtual_price\s*\(|"
    r"\.get_p\s*\(|\.price_x96\s*\(|\.current_sqrt_price\s*\("
)

_TWAP_TOKENS = (
    "twap", "TWAP", "time_weighted", "accumulator",
    "cumulative", "observe", "deviation", "median",
    "oracle_price", "chainlink", "pyth", "reflector",
    "price_oracle", "staleness", "heartbeat",
)

_CONSUMER_TOKENS = (
    "mint", "borrow", "collateral", "health", "ltv",
    "price", "quote", "swap_out", "redeem",
)


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        name = fn_name(fn, source)
        if name.startswith("set_") or name.startswith("init") \
                or name.startswith("admin_"):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_text = text_of(body, source)

        if not _RESERVE_RE.search(body_text):
            continue
        # TWAP / oracle backstop already in place?
        lower = body_text.lower()
        if any(tok.lower() in lower for tok in _TWAP_TOKENS):
            continue

        # Must feed into a consumer OR appear in a ratio.
        has_ratio = bool(re.search(r"[a-z_]+_reserves?\s*[\*/]|"
                                   r"reserves\s*[\*/]|"
                                   r"\breserve\b\s*[\*/]",
                                   body_text, re.IGNORECASE))
        has_consumer = any(tok in lower for tok in _CONSUMER_TOKENS)
        if not (has_ratio or has_consumer):
            continue

        # Locate the reserves read node
        reserve_node = None
        for n in walk_no_nested_fn(body):
            if n.type != "call_expression":
                continue
            if _RESERVE_RE.search(text_of(n, source)):
                reserve_node = n
                break
        if reserve_node is None:
            continue

        line, col = line_col(reserve_node)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(reserve_node, source),
            "message": (
                f"fn `{name}` reads live pool reserves / spot slot and "
                f"uses the ratio directly in a price / mint / borrow / "
                f"health decision — no TWAP, accumulator, or deviation "
                f"band — flash-loan price manipulation."
            ),
        })
    return hits

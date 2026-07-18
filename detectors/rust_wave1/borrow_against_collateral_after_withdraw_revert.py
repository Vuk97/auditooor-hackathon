"""
borrow_against_collateral_after_withdraw_revert.py

Flags withdraw-flow functions that use `.unwrap_or(...)` /
`.unwrap_or_default()` / `.ok()` to swallow a transfer-out failure, and
then continue to update collateral accounting — meaning collateral is
"seized" even though the underlying transfer silently failed.

Heuristic:
  1. Function name contains `withdraw` / `redeem` / `liquidate_`.
  2. Body contains `.transfer(...)` wrapped in a call chain ending in
     `.ok()` OR `.unwrap_or(...)` OR `.unwrap_or_default()` — i.e. the
     failure is swallowed.
  3. Body subsequently reduces a collateral balance (`.set(...)` on a
     key containing `collateral`, `balance`, `shares`, `principal`).

If step 3 follows step 2 in file order → flag.
"""

from __future__ import annotations

import re

from _util import (
    function_items, fn_body, fn_name, text_of, walk_no_nested_fn,
    line_col, snippet_of, in_test_cfg,
)


_FN_HINTS = ("withdraw", "redeem", "liquidate_")

_BALANCE_HINTS = (
    "collateral", "balance", "shares", "principal",
    "user_balance", "supply_balance", "collateral_balance",
)


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        name = fn_name(fn, source)
        if not any(h in name for h in _FN_HINTS):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_text = text_of(body, source)

        # find `try_invoke` / `.transfer(...).ok()` / `.unwrap_or` pattern
        swallow_match = re.search(
            r"(transfer|transfer_from|try_invoke_contract)[^;]*"
            r"(\.ok\(\)|\.unwrap_or\b|\.unwrap_or_default\b)",
            body_text, re.DOTALL
        )
        if not swallow_match:
            continue
        swallow_end = swallow_match.end()

        # Next: a storage .set() after swallow_end referencing a balance hint
        after = body_text[swallow_end:]
        set_match = re.search(
            r"\.set\s*\([^)]*\)", after, re.DOTALL
        )
        if not set_match:
            continue
        surrounding_window = after[:set_match.end() + 120]
        if not any(h in surrounding_window for h in _BALANCE_HINTS):
            continue
        # Flag the fn
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(body, source, 200),
            "message": (
                f"fn `{name}` swallows a transfer-out failure with "
                f"`.ok()` / `.unwrap_or(...)` and then updates collateral/"
                f"balance accounting — seizure proceeds even if the "
                f"transfer silently failed."
            ),
        })
    return hits

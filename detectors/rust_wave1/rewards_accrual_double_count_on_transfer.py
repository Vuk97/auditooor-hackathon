"""
rewards_accrual_double_count_on_transfer.py

Flags token `transfer` / `transfer_from` functions that invoke an
incentives / accrual callback for both `from` and `to` without an
`from != to` self-transfer guard. On a self-transfer the callback runs
twice for the same account and double-counts accrual.

Heuristic:
  1. Function name is `transfer` / `transfer_from` / `transferFrom`.
  2. Body contains at least TWO calls matching:
        handle_action(...) / accrue_to_user(...) / update_user_rewards(...)
        / update_rewards_for / _handle_action
     where the arg list references `from` or `to` (or the caller-supplied
     `from`/`to`/`user` identifier).
  3. Body does NOT contain an early-exit `if from == to`/`if from != to`
     guard or a `return` inside such a guard.
"""

from __future__ import annotations

import re

from _util import (
    function_items, fn_body, fn_name, text_of, walk_no_nested_fn,
    line_col, snippet_of, in_test_cfg,
)


_TRANSFER_NAMES = ("transfer", "transfer_from", "transferFrom",
                    "_transfer", "_transfer_from")

_HANDLER_PATTERNS = (
    r"handle_action\s*\(",
    r"accrue_to_user\s*\(",
    r"update_user_rewards\s*\(",
    r"update_rewards_for\s*\(",
    r"_handle_action\s*\(",
    r"distribute_rewards_for\s*\(",
    r"update_accrual\s*\(",
)

_SELF_TRANSFER_GUARDS = (
    r"if\s+from\s*==\s*to",
    r"if\s+to\s*==\s*from",
    r"if\s+from\s*!=\s*to",
    r"from\s*==\s*to",
    r"sender\s*==\s*recipient",
)


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        name = fn_name(fn, source)
        if name not in _TRANSFER_NAMES:
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_text = text_of(body, source)

        # Count handler call sites
        handler_count = 0
        for pat in _HANDLER_PATTERNS:
            handler_count += len(re.findall(pat, body_text))
        if handler_count < 2:
            continue

        # Guard?
        if any(re.search(p, body_text) for p in _SELF_TRANSFER_GUARDS):
            continue

        line, col = line_col(fn)
        hits.append({
            "severity": "medium",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source, 200),
            "message": (
                f"fn `{name}` calls rewards-accrual handler >= 2 times for "
                f"from/to without an `from != to` self-transfer guard — "
                f"self-transfer double-counts accrual."
            ),
        })
    return hits

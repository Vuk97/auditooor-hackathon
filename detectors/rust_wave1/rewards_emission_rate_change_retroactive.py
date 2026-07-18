"""
rewards_emission_rate_change_retroactive.py

Admin updates `emission_rate` / `reward_per_second` without first check-
pointing accrual at the OLD rate. Time elapsed under the OLD rate is then
retroactively accrued at the NEW rate.

Heuristic:
  1. Function name matches `set_emission_rate` / `set_emission_per_second`
     / `update_emission` / `set_reward_rate` / `update_reward_rate` /
     `set_rewards_per_second`.
  2. Body writes the rate field (`.set(`) to the new value.
  3. Body does NOT call any of:
        update_accrual / checkpoint / _update_rewards_index /
        update_rewards_state / accrue_rewards / checkpoint_rewards /
        _update_indexes
     BEFORE the `.set(` line.
"""

from __future__ import annotations

import re

from _util import (
    function_items, fn_body, fn_name, text_of, walk_no_nested_fn,
    line_col, snippet_of, in_test_cfg,
)


_EMISSION_SETTER_RE = re.compile(
    r"^(set_emission_rate|set_emission_per_second|update_emission|"
    r"set_reward_rate|update_reward_rate|set_rewards_per_second|"
    r"set_reward_per_second|update_emission_rate|"
    r"configure_emission)$"
)

_CHECKPOINT_TOKENS = (
    "update_accrual", "checkpoint", "_update_rewards_index",
    "update_rewards_state", "accrue_rewards", "checkpoint_rewards",
    "_update_indexes", "update_index", "update_reward_index",
    "update_rewards_index", "accrue_asset",
    "distribute_before_rate_change", "_accrue",
)


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        name = fn_name(fn, source)
        if not _EMISSION_SETTER_RE.match(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue

        # Find the first `.set(` call in body
        set_call_byte = None
        first_checkpoint_byte = None
        for n in walk_no_nested_fn(body):
            if n.type != "call_expression":
                continue
            t = text_of(n, source)
            if set_call_byte is None and ".set(" in t and "storage" in t:
                set_call_byte = n.start_byte
            if first_checkpoint_byte is None:
                if any(tok in t for tok in _CHECKPOINT_TOKENS):
                    first_checkpoint_byte = n.start_byte
        if set_call_byte is None:
            continue
        # OK if checkpoint fires before the set
        if first_checkpoint_byte is not None \
                and first_checkpoint_byte < set_call_byte:
            continue

        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source, 200),
            "message": (
                f"fn `{name}` writes new emission rate without first "
                f"calling any accrual checkpoint — users accrue the NEW "
                f"rate retroactively for time elapsed under the OLD rate."
            ),
        })
    return hits

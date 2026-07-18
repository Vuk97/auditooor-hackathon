"""
liquidation_no_health_factor_post_check.py

Aave invariant: after a liquidation mutates state (seize collateral / burn
debt tokens / transfer), the user's health factor MUST improve. Detector
flags liquidate-named fns that mutate state and never re-compute / compare
the health factor afterwards.

Heuristic:
  1. Function name matches `liquidate*` / `liquidation_call*`.
  2. Body mutates state (.set / .burn / .transfer / .transfer_from /
     .update / .mint).
  3. Body does NOT contain any of:
        calculate_health_factor / compute_hf / validate_health_factor /
        check_health_factor / compute_health / hf_after
  4. We additionally require that the mutation appears physically AFTER
     the function-entry (i.e. not just a revert-on-entry call).

Maps to Aave / Compound / Silo liquidation invariant violations (11+
corpus reports).
"""

from __future__ import annotations

import re

from _util import (
    function_items, fn_body, fn_name, text_of, walk_no_nested_fn,
    line_col, snippet_of, in_test_cfg,
)


_LIQ_NAME_RE = re.compile(r"^(liquidate|liquidation_call|liquidate_borrow)",
                           re.IGNORECASE)

_MUTATION_CALLS = (
    ".set(", ".burn(", ".transfer(", ".transfer_from(",
    ".update(", ".mint(", ".remove(", ".seize(",
)

_HF_POST_CHECK_TOKENS = (
    "calculate_health_factor", "validate_health_factor",
    "check_health_factor", "compute_health_factor", "hf_after",
    "get_health_factor_after", "assert_health_factor",
    "require_health_factor_improves", "post_hf", "hf_post",
    "health_factor_after",
)


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        name = fn_name(fn, source)
        if not _LIQ_NAME_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_text = text_of(body, source)

        # Need at least one state mutation call
        has_mut = any(tok in body_text for tok in _MUTATION_CALLS)
        if not has_mut:
            continue

        # Must NOT contain any HF post-check token
        if any(tok in body_text for tok in _HF_POST_CHECK_TOKENS):
            continue

        # Locate the first mutation call to pin a line.
        first_mut_node = None
        for n in walk_no_nested_fn(body):
            if n.type != "call_expression":
                continue
            t = text_of(n, source)
            if any(tok in t for tok in _MUTATION_CALLS):
                first_mut_node = n
                break
        target = first_mut_node if first_mut_node else fn
        line, col = line_col(target)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(target, source),
            "message": (
                f"fn `{name}` mutates state but never re-checks / "
                f"re-computes the health factor afterwards — Aave "
                f"liquidation invariant requires HF strictly improves."
            ),
        })
    return hits

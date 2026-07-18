"""
circuit_breaker_staleness_bypass.py

Flags oracle-resolution functions that call one oracle source (Reflector /
fallback / custom / manual override) but omit a circuit-breaker or staleness
check before consuming the returned price.

Indicators:
  1. A function whose body calls AT LEAST ONE oracle source among:
         - `Reflector::new(...).lastprice(...)` / `.twap(...)`
         - `get_price_with_protection*`
         - `query_custom_oracle`, `query_batch_adapter_direct`
         - reads `manual_override_price`
     but has NO call to any of:
         - `validate_price_staleness` / `validate_price_freshness`
         - `validate_price_change`
         - `is_circuit_breaker_active` / `get_circuit_breaker_state`
         - `circuit_breaker_check`
  2. A function that reads a cached price via
     `storage::get_last_price_data` / `.get_last_price` / `.get_cached_price`
     without a staleness call in the same body.

The detector only fires for fns whose bodies reference at least one
oracle/source call — it will not fire on generic getters.
"""

from __future__ import annotations

import re

from _util import (
    function_items, fn_body, fn_name, text_of, walk_no_nested_fn,
    line_col, snippet_of, in_test_cfg,
)


_SOURCE_PATTERNS = [
    r"\.lastprice\s*\(",           # Reflector
    r"\.twap\s*\(",                # Reflector TWAP
    r"get_price_with_protection",  # K2 oracle helper
    r"query_custom_oracle",
    r"query_batch_adapter_direct",
    r"manual_override_price",
    r"Reflector\s*::\s*new",
    r"\.get_price\s*\(",           # generic custom oracle trait
]

_CACHED_READ_PATTERNS = [
    r"get_last_price_data",
    r"get_last_price\b",
    r"get_cached_price",
]

_GUARD_PATTERNS = [
    r"validate_price_staleness",
    r"validate_price_freshness",
    r"validate_price_change",
    r"is_circuit_breaker_active",
    r"get_circuit_breaker_state",
    r"circuit_breaker_check",
    r"check_staleness",
    r"check_freshness",
]


def _has_any(text: str, patterns: list[str]) -> bool:
    return any(re.search(p, text) for p in patterns)


def _any_source_call_node(body, source: bytes):
    """Return the first call_expression node that matches a source pattern,
    or None."""
    for n in walk_no_nested_fn(body):
        if n.type != "call_expression":
            continue
        t = text_of(n, source)
        for pat in _SOURCE_PATTERNS:
            if re.search(pat, t):
                return n, "source"
    # Check for cached reads separately
    for n in walk_no_nested_fn(body):
        if n.type != "call_expression":
            continue
        t = text_of(n, source)
        for pat in _CACHED_READ_PATTERNS:
            if re.search(pat, t):
                return n, "cache"
    return None, None


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        name = fn_name(fn, source)
        # Skip admin/setter/reset helpers — they legitimately touch sources
        # without needing freshness guards at call time.
        if name.startswith(("set_", "reset_", "admin", "initialize",
                            "remove_", "add_", "update_reflector",
                            "pause", "unpause", "upgrade", "propose_",
                            "accept_", "cancel_")):
            continue

        body = fn_body(fn)
        if body is None:
            continue
        body_text = text_of(body, source)

        node, kind = _any_source_call_node(body, source)
        if node is None:
            continue

        if _has_any(body_text, _GUARD_PATTERNS):
            continue

        line, col = line_col(node)
        if kind == "source":
            msg = (f"fn `{name}` calls an oracle source without any circuit-"
                   f"breaker / staleness guard (no validate_price_* / "
                   f"is_circuit_breaker_active found in the body).")
        else:
            msg = (f"fn `{name}` consumes a cached oracle price without any "
                   f"staleness validation in the body.")
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(node, source),
            "message": msg,
        })
    return hits

"""
frontrun_initialize_takeover.py

Flags `initialize` / `init` / `__constructor` fns that write an admin or
owner key to storage without:
  - checking that it has not already been initialized
    (`has(INITIALIZED)` / `get(ADMIN).is_some()` pattern); AND
  - calling `.require_auth()` on some gated address.

The bug class: attacker front-runs initialization and becomes admin.

Heuristic:
  1. fn_name in {initialize, init, __constructor, setup}.
  2. Body writes to a key whose name contains `admin`, `owner`,
     `governance`, `initialized`.
  3. Body has NO `has(` check AND NO early-panic/require on an existing
     admin read AND NO `.require_auth()` call.
"""

from __future__ import annotations

import re

from _util import (
    function_items, fn_body, fn_name, text_of, walk_no_nested_fn,
    line_col, snippet_of, in_test_cfg,
)


_INIT_NAMES = {"initialize", "init", "__constructor", "setup",
               "initialize_contract", "init_pool"}

_ADMIN_HINTS = ("admin", "owner", "governance", "initialized",
                "Admin", "Owner", "INITIALIZED", "ADMIN", "Initialized")


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        name = fn_name(fn, source)
        if name not in _INIT_NAMES:
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_text = text_of(body, source)

        # must write to an admin-ish key
        if not re.search(r"\.set\s*\(", body_text):
            continue
        if not any(h in body_text for h in _ADMIN_HINTS):
            continue

        # has() check or existing-admin read?
        if re.search(r"\.has\s*\(", body_text):
            continue
        if re.search(r"\.get\s*\([^)]*\)\.is_some\(\)", body_text):
            continue
        if re.search(r"if[^{]*(already_initialized|Initialized|is_initialized|panic_with_error)",
                     body_text):
            continue
        # require_auth present?
        if ".require_auth(" in body_text:
            continue

        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(body, source, 200),
            "message": (
                f"fn `{name}` writes admin/owner state with no "
                f"`has()`-initialized guard and no `require_auth()` — "
                f"front-runnable initialization (admin takeover)."
            ),
        })
    return hits

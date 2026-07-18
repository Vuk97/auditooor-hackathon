"""
r94_pause_function_no_auth.py

Flags public `pause` / `unpause` / `emergency_stop` / `set_paused` fns
that mutate a paused flag but never call `.require_auth()`, `check_admin`,
or a gated helper.  An attacker can grief the protocol by freezing
all state transitions.

Maps to Solidity:
  - glider-pause-function-no-access-control
  - glider-pause-functions-lack-access-control
  - rollup-pause-proving-permissionless-dos-finalization

Heuristic:
  - fn name contains `pause`, `unpause`, `emergency_stop`, `freeze`,
    `halt`, or fn sets a key named `PAUSED`/`paused`/`is_paused`.
  - Body writes storage (persistent/instance/temporary).
  - Body does NOT contain `.require_auth(` AND does NOT call any helper
    whose name starts with `check_`, `assert_`, `only_`, `_authed_`,
    or `_admin_`.
"""

from __future__ import annotations

import re

from _util import (
    functions_in_contractimpl, fn_body, fn_name, is_pub, text_of,
    walk_no_nested_fn, line_col, snippet_of,
)


_PAUSE_RE = re.compile(
    r"(^|_)(pause|unpause|emergency_stop|freeze|halt|set_paused)$",
    re.IGNORECASE,
)

_PAUSE_KEY_TOKENS = ("PAUSED", "paused", "IS_PAUSED", "is_paused",
                     "Pause", "Frozen", "frozen", "IS_HALTED")

_AUTH_HELPER_RE = re.compile(
    r"\b(check_|assert_|only_|_authed_|_admin_|require_admin|"
    r"require_governance|require_owner)"
)


def _has_storage_write(body, source):
    for n in walk_no_nested_fn(body):
        if n.type != "call_expression":
            continue
        callee = None
        for c in n.children:
            if c.type == "field_expression":
                callee = c
                break
        if callee is None:
            continue
        method = None
        for c in callee.children:
            if c.type == "field_identifier":
                method = text_of(c, source)
        if method not in ("set", "update", "remove"):
            continue
        ctxt = text_of(callee, source)
        if ("storage()" in ctxt or ".persistent()" in ctxt
                or ".instance()" in ctxt or ".temporary()" in ctxt):
            return n
    return None


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
        body_text = text_of(body, source)

        is_pause_name = bool(_PAUSE_RE.search(name))
        writes_pause_key = any(tok in body_text for tok in _PAUSE_KEY_TOKENS)
        if not (is_pause_name or writes_pause_key):
            continue

        mut_node = _has_storage_write(body, source)
        if mut_node is None:
            continue

        if ".require_auth(" in body_text:
            continue
        if _AUTH_HELPER_RE.search(body_text):
            continue

        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(mut_node, source),
            "message": (
                f"pub fn `{name}` toggles a pause/emergency-stop flag "
                f"without `.require_auth()` or any admin gate — anyone "
                f"can freeze/unfreeze the protocol (DoS / griefing)."
            ),
        })
    return hits

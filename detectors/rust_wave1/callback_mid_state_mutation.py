"""
callback_mid_state_mutation.py

Flags Soroban callback entry-points that mutate protocol-critical storage
without first snapshotting / guarding against the caller.  Maps to
wave7/8 callback-state class (swap_callback_reentrancy, flashloan_callback,
exchange_rate_no_reset_on_zero_supply).

Heuristic:
  - A "callback-like" function is a pub fn in a #[contractimpl] whose NAME
    ends in `_callback`, `_cb`, or matches common SDK callback names
    (`on_*`, `receive_*`, `callback`).
  - The body writes to storage for protocol-critical keys (debt, supply,
    allowance, borrow, collateral, total).
  - The body does NOT start with a `require_auth()` on the caller AND does
    NOT snapshot any state (i.e., does NOT have a `.get(` storage read
    before the write of the same key).
"""

from __future__ import annotations

import re

from _util import (
    functions_in_contractimpl, fn_body, fn_name, is_pub, text_of,
    walk_no_nested_fn, line_col, snippet_of,
)


_CALLBACK_RE = re.compile(
    r'(callback$|_cb$|^on_|^receive_|^handle_)', re.IGNORECASE
)
_CRITICAL_KEY_RE = re.compile(
    r'(debt|supply|allowance|borrow|collateral|total|balance|reserve)',
    re.IGNORECASE
)


def _find_storage_writes(body, source):
    """Yield (call_node, key_text, write_method) for every storage set/update
    inside `body`."""
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
        if method not in ("set", "update"):
            continue
        ctxt = text_of(callee, source)
        if not ("storage()" in ctxt or ".persistent()" in ctxt
                or ".instance()" in ctxt or ".temporary()" in ctxt):
            continue
        # Look at the first argument (the key)
        args = None
        for c in n.children:
            if c.type == "arguments":
                args = c
                break
        key_text = text_of(args, source) if args is not None else ""
        yield n, key_text, method


def _has_require_auth(body, source):
    for n in walk_no_nested_fn(body):
        if n.type != "call_expression":
            continue
        t = text_of(n, source)
        if ".require_auth(" in t:
            return True
    return False


def _has_snapshot_get(body, source, before_byte):
    """True if a `storage().<tier>().get(...)` call appears before `before_byte`."""
    for n in walk_no_nested_fn(body):
        if n.type != "call_expression":
            continue
        if n.start_byte >= before_byte:
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
        if method != "get":
            continue
        ctxt = text_of(callee, source)
        if "storage()" in ctxt or ".persistent()" in ctxt \
                or ".instance()" in ctxt or ".temporary()" in ctxt:
            return True
    return False


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        if not _CALLBACK_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        # Find a write on a critical key.
        critical_write = None
        for call_n, key_text, method in _find_storage_writes(body, source):
            if _CRITICAL_KEY_RE.search(key_text):
                critical_write = (call_n, key_text)
                break
        if critical_write is None:
            continue
        if _has_require_auth(body, source):
            continue
        if _has_snapshot_get(body, source, critical_write[0].start_byte):
            continue
        call_n, key_text = critical_write
        line, col = line_col(call_n)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(call_n, source),
            "message": (f"callback-like `{name}` writes critical storage "
                        f"{key_text[:60]} without prior `require_auth` or "
                        f"snapshot `.get(...)` — callback mid-state mutation."),
        })
    return hits

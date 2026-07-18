"""
missing_input_validation_zero_address.py

Flags `pub fn` inside `#[contractimpl]` that take an `Address` parameter and
store it in persistent / instance storage without any zero-address /
default-Address guard.

Maps to wave11 missing-input-validation class (order_tokenid_zero_sentinel +
zero-address-setter variants).

Heuristic:
  - Iterate pub fns in contractimpl whose name starts with `set_`, `update_`,
    `init`, `initialize`, `register`, or whose body stores an Address-typed
    parameter via `env.storage().*.set(...)`.
  - For each Address parameter that flows into a storage write call:
      - Check if the function body contains ANY guard on that parameter
        against zero (e.g. `== Address::default()`, `.eq(&Address::from_string(...))`,
        `if x == Address::...`).
      - If no guard is found, flag.
"""

from __future__ import annotations

import re

from _util import (
    functions_in_contractimpl, fn_body, fn_name, is_pub, text_of,
    walk_no_nested_fn, line_col, snippet_of,
)


_INIT_RE = re.compile(
    r'^(set_|update_|init|initialize|register|configure)', re.IGNORECASE
)


def _address_params(fn_node, source):
    """Yield names of parameters whose type is `Address`."""
    for c in fn_node.children:
        if c.type != "parameters":
            continue
        for p in c.children:
            if p.type != "parameter":
                continue
            ptext = text_of(p, source)
            if re.search(r':\s*Address\b', ptext) and "Env" not in ptext.split(":")[1]:
                # get name
                m = re.match(r'\s*(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:', ptext)
                if m:
                    yield m.group(1)


def _stores_param(body, source, param_name):
    """Return the call_node where `param_name` is set into storage, else None."""
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
        args = None
        for c in n.children:
            if c.type == "arguments":
                args = c
                break
        if args is None:
            continue
        args_text = text_of(args, source)
        # Is param_name a whole-word substring in the args?
        if re.search(r'\b' + re.escape(param_name) + r'\b', args_text):
            return n
    return None


def _has_zero_guard(body, source, param_name):
    """True if the body contains any zero/default comparison on `param_name`."""
    btxt = text_of(body, source)
    # `param == Address::default()` / `Address::from_str(&env, "")`
    # or `if param == <anything>` where `<anything>` contains Address or default
    patterns = [
        rf'{re.escape(param_name)}\s*==\s*Address::',
        rf'Address::[a-zA-Z_]+\s*\(.*?\)\s*==\s*{re.escape(param_name)}',
        rf'{re.escape(param_name)}\.eq\s*\(\s*&?Address::',
        rf'panic_with_error.*{re.escape(param_name)}',
        # require_auth is not a zero-check, but if the pattern is to
        # `require_auth` the address, we treat it as basic validation.
        rf'{re.escape(param_name)}\.require_auth\s*\(',
    ]
    for p in patterns:
        if re.search(p, btxt):
            return True
    return False


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        body = fn_body(fn)
        if body is None:
            continue

        # Collect all Address params
        params = list(_address_params(fn_node=fn, source=source))
        if not params:
            continue

        # Apply to init-like functions primarily — these are where unchecked
        # zero-addresses bite.  We still allow any function that stores the
        # param to be flagged, but prefer _INIT_RE names for higher signal.
        is_init_shape = bool(_INIT_RE.match(name))

        for p in params:
            store_node = _stores_param(body, source, p)
            if store_node is None:
                continue
            if _has_zero_guard(body, source, p):
                continue
            # Lower the severity for non-init functions.
            sev = "med" if is_init_shape else "low"
            line, col = line_col(store_node)
            hits.append({
                "severity": sev,
                "line": line,
                "col": col,
                "snippet": snippet_of(store_node, source),
                "message": (f"pub fn `{name}` stores Address parameter `{p}` "
                            f"without any zero / default-Address guard."),
            })
    return hits

"""
missing_require_auth_on_mutation.py

Flags public fns inside #[contractimpl] that mutate env.storage() without any
`.require_auth()` call on an Address parameter.

Heuristic: look for calls like `env.storage().persistent().set(...)` or
`.instance().set(...)` / `.temporary().set(...)` / `.update(...)` /
`.remove(...)` and ensure the same function body contains at least one
`<something>.require_auth()` call.

False positives we accept:
  - Internal helpers exposed through #[contractimpl] that should only be
    callable by owning contract (flagged — worth reviewing anyway).
  - Functions that check auth via a nested helper call (e.g. _only_admin(env))
    that itself calls require_auth inside.

Pattern class: Halborn §7.1 — missing access control on mutating operations.
"""

from __future__ import annotations

from _util import (
    functions_in_contractimpl, fn_body, fn_name, is_pub, text_of,
    walk_no_nested_fn, line_col, snippet_of,
)


MUTATING_METHODS = {"set", "update", "remove", "extend_ttl",
                    "extend_instance_ttl"}


def _has_storage_mutation(body, source):
    if body is None:
        return None
    for n in walk_no_nested_fn(body):
        if n.type != "call_expression":
            continue
        # call_expression → field_expression (callee) + arguments
        callee = n.child_by_field_name("function") if hasattr(
            n, "child_by_field_name") else None
        if callee is None:
            # fall back to first child that's field_expression/scoped
            for c in n.children:
                if c.type in ("field_expression",
                              "scoped_identifier", "identifier"):
                    callee = c
                    break
        if callee is None or callee.type != "field_expression":
            continue
        # last identifier is method name
        method = None
        for c in callee.children:
            if c.type == "field_identifier":
                method = text_of(c, source)
        if method not in MUTATING_METHODS:
            continue
        # Check callee text contains storage/persistent/instance/temporary
        ctxt = text_of(callee, source)
        if ("storage()" in ctxt or ".persistent()" in ctxt
                or ".instance()" in ctxt or ".temporary()" in ctxt):
            return n
    return None


def _has_require_auth(body, source):
    if body is None:
        return False
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
        for c in callee.children:
            if c.type == "field_identifier" and \
                    text_of(c, source) == "require_auth":
                return True
    return False


def run(tree, source: bytes, filepath: str):
    hits = []
    root = tree.root_node
    for fn, impl in functions_in_contractimpl(root, source):
        if not is_pub(fn, source):
            continue
        body = fn_body(fn)
        mut_node = _has_storage_mutation(body, source)
        if mut_node is None:
            continue
        if _has_require_auth(body, source):
            continue
        name = fn_name(fn, source)
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(mut_node, source),
            "message": (f"pub fn `{name}` mutates storage without calling "
                        f"`.require_auth()` on any address in its body "
                        f"(Halborn §7.1 class)."),
        })
    return hits

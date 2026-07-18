"""
missing_ttl_bump_on_persistent_read.py

Flags any `pub fn` that reads from persistent() / instance() storage via
`.get(` without calling `extend_ttl` / `extend_instance_ttl` / `bump` anywhere
in the same function body.  Halborn §7.16 class.

This is a lint — not every read needs a bump (e.g. admin views). We keep
severity low and accept some FPs; the value is a candidate list for
cold-reading.
"""

from __future__ import annotations

from _util import (
    function_items, fn_body, fn_name, is_pub, text_of, walk_no_nested_fn,
    line_col, snippet_of, in_test_cfg,
)


def _find_persistent_reads(body, source):
    reads = []
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
        if method != "get":
            continue
        ctxt = text_of(callee, source)
        if ".persistent()" in ctxt or ".instance()" in ctxt:
            reads.append(n)
    return reads


def _has_ttl_bump(body, source):
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
            if c.type == "field_identifier":
                m = text_of(c, source)
                if m in ("extend_ttl", "extend_instance_ttl", "bump"):
                    return True
    return False


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn in function_items(tree.root_node):
        if not is_pub(fn, source):
            continue
        if in_test_cfg(fn, source):
            continue
        name = fn_name(fn, source)
        # Skip obvious read-only view/getter names
        if name.startswith("get_") or name.startswith("view_") or \
                name in ("balance", "allowance", "name", "symbol", "decimals",
                         "total_supply", "total_shares"):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        reads = _find_persistent_reads(body, source)
        if not reads:
            continue
        if _has_ttl_bump(body, source):
            continue
        line, col = line_col(reads[0])
        hits.append({
            "severity": "low",
            "line": line,
            "col": col,
            "snippet": snippet_of(reads[0], source),
            "message": (f"pub fn `{name}` reads persistent/instance storage "
                        f"without calling extend_ttl/extend_instance_ttl "
                        f"(Halborn §7.16)."),
        })
    return hits

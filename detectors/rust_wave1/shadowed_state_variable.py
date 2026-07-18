"""
shadowed_state_variable.py

Flags local bindings (`let <name> = ...`) inside pub contract fns where
`<name>` is also a storage key constant defined at module scope
(pattern: `pub const <NAME>: Symbol = symbol_short!("<NAME>")` OR the key
enum variant `DataKey::<CamelCase>`).

Narrower variant: local `let admin = ...` inside a fn when a module-level
const `ADMIN: Symbol` exists — the local often reads the stale value while
a later write goes to the storage key, or vice-versa.

Heuristic:
  1. Collect module-level const idents whose type is `Symbol` or value
     uses `symbol_short!` / `Symbol::new`.
  2. Inside each fn body, find `let <ident> = ...` where `<ident>` (any
     case) matches one of the const names (case-insensitively).
  3. Emit a `low` hit.
"""

from __future__ import annotations

import re

from _util import (
    function_items, fn_body, fn_name, text_of, walk,
    walk_no_nested_fn, line_col, snippet_of, in_test_cfg,
)


def _module_level_storage_consts(root, source: bytes) -> set[str]:
    names = set()
    for n in root.children:
        if n.type != "const_item":
            continue
        t = text_of(n, source)
        if ": Symbol" not in t and "symbol_short!" not in t \
                and "Symbol::new" not in t:
            continue
        # extract ident
        m = re.search(r"const\s+([A-Za-z_][A-Za-z0-9_]*)", t)
        if m:
            names.add(m.group(1))
    return names


def run(tree, source: bytes, filepath: str):
    root = tree.root_node
    consts = _module_level_storage_consts(root, source)
    if not consts:
        return []
    consts_lower = {c.lower(): c for c in consts}
    hits = []
    for fn in function_items(root):
        if in_test_cfg(fn, source):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        for n in walk_no_nested_fn(body):
            if n.type != "let_declaration":
                continue
            # Extract bound ident
            bound = None
            for c in n.children:
                if c.type == "identifier":
                    bound = text_of(c, source)
                    break
                if c.type == "mutable_specifier":
                    # next ident
                    idx = n.children.index(c)
                    for cc in n.children[idx + 1:]:
                        if cc.type == "identifier":
                            bound = text_of(cc, source)
                            break
                    break
            if not bound:
                continue
            if bound.lower() in consts_lower:
                line, col = line_col(n)
                hits.append({
                    "severity": "low",
                    "line": line,
                    "col": col,
                    "snippet": snippet_of(n, source),
                    "message": (
                        f"local `let {bound}` in fn `{fn_name(fn, source)}` "
                        f"shadows module-level storage-key const "
                        f"`{consts_lower[bound.lower()]}` — easy to read "
                        f"one and write the other."
                    ),
                })
    return hits

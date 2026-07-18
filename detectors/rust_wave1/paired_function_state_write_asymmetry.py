"""
paired_function_state_write_asymmetry.py

Flags function pairs (`add_X` / `remove_X`, `enable_X` / `disable_X`,
`lock_X` / `unlock_X`, `register_X` / `deregister_X`, `grant_X` / `revoke_X`,
`mint_X` / `burn_X`) declared in the SAME file/contract where the pair writes
a different SET of storage keys.

Maps to wave9 symmetry class (paired_function_state_write_diff).

IMPORTANT — SKILL_ISSUE #43 avoidance:
  Only pair functions with the SAME stem (e.g. `add_admin` ↔ `remove_admin`).
  NEVER cross-pair (`add_admin` ↔ `remove_operator`).  That was the bug that
  killed the earlier Glider port.

Storage key detection:
  We look at the FIRST argument of any `env.storage().*.set(...)` /
  `.remove(...)` / `.update(...)` / `.get(...)` that is inside the function
  body, extract its textual form (typically `&Symbol::new(&env, "NAME")` or
  a `DataKey::Variant(...)` literal), and stringify it.
"""

from __future__ import annotations

import re

from _util import (
    functions_in_contractimpl, fn_body, fn_name, is_pub, text_of,
    walk_no_nested_fn, line_col, snippet_of,
)


_PAIRS = [
    ("add_", "remove_"),
    ("enable_", "disable_"),
    ("lock_", "unlock_"),
    ("register_", "deregister_"),
    ("grant_", "revoke_"),
    ("mint_", "burn_"),
    ("open_", "close_"),
]


def _mutation_keys(body, source) -> set[str]:
    """Return the stringified set of storage keys this body writes OR removes."""
    keys: set[str] = set()
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
        arg_children = [c for c in args.children
                        if c.type not in ("(", ")", ",")]
        if not arg_children:
            continue
        key_expr = text_of(arg_children[0], source).strip()
        # Normalise: strip leading `&`, whitespace
        key_expr = key_expr.lstrip("&").strip()
        # Drill down to the interesting discriminant:
        #   Symbol::new(&env, "ADMINS") → key = "ADMINS"
        m = re.search(r'Symbol::new\s*\([^,]+,\s*"([^"]+)"\s*\)', key_expr)
        if m:
            keys.add(f'Symbol:{m.group(1)}')
            continue
        #   symbol_short!("ADMINS")
        m = re.search(r'symbol_short!\s*\(\s*"([^"]+)"\s*\)', key_expr)
        if m:
            keys.add(f'Symbol:{m.group(1)}')
            continue
        #   DataKey::Admins or DataKey::Admins(addr)
        m = re.search(r'DataKey::([A-Za-z_][A-Za-z0-9_]*)', key_expr)
        if m:
            keys.add(f'DataKey:{m.group(1)}')
            continue
        # fallback: use first token
        keys.add(f'raw:{key_expr[:48]}')
    return keys


def run(tree, source: bytes, filepath: str):
    hits = []
    # Collect all pub contractimpl fns with their bodies.
    fns: dict[str, tuple[object, set[str]]] = {}
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        if not is_pub(fn, source):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        name = fn_name(fn, source)
        keys = _mutation_keys(body, source)
        fns[name] = (fn, keys)

    # For each name, see if it starts with one of the positive prefixes,
    # find its same-stem counterpart.
    seen_pairs: set[tuple[str, str]] = set()
    for name, (fn, keys) in fns.items():
        for pos, neg in _PAIRS:
            if name.startswith(pos):
                stem = name[len(pos):]
                counterpart = neg + stem
                if counterpart not in fns:
                    continue
                pair_key = tuple(sorted((name, counterpart)))
                if pair_key in seen_pairs:
                    continue
                seen_pairs.add(pair_key)
                other_fn, other_keys = fns[counterpart]
                # Ignore empty key sets (nothing written — not our business).
                if not keys or not other_keys:
                    continue
                if keys == other_keys:
                    continue
                diff_in_a = keys - other_keys
                diff_in_b = other_keys - keys
                # Flag the one that writes extra keys (the opposite is more
                # likely to be missing a cleanup).
                rep_fn = fn if diff_in_a else other_fn
                line, col = line_col(rep_fn)
                hits.append({
                    "severity": "med",
                    "line": line,
                    "col": col,
                    "snippet": snippet_of(rep_fn, source),
                    "message": (f"asymmetric state writes between `{name}` "
                                f"(keys={sorted(keys)}) and `{counterpart}` "
                                f"(keys={sorted(other_keys)}). Paired "
                                f"functions should touch the same storage keys."),
                })
                break
    return hits

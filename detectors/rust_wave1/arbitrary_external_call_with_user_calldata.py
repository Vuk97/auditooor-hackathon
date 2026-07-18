"""
arbitrary_external_call_with_user_calldata.py

Flags pub contract functions that invoke another contract via
`env.invoke_contract(...)` / `env.try_invoke_contract(...)` where BOTH the
target address AND the function symbol/args are user-controlled (come from
this function's parameters).

Class: treasury drain — attacker supplies arbitrary (target, selector, args)
and the contract happily forwards its own authority.

Heuristic:
  1. fn is pub inside #[contractimpl]
  2. body contains `env.invoke_contract(...)` or
     `.invoke_contract(&env, ...)` style call
  3. target argument is an ident equal to an Address parameter of the fn
     AND (symbol or args) argument also derives from a parameter

False-positive filters:
  - target is a storage-read (e.g. `Self::token(env)`) — safe (admin-set).
  - target is a literal or scoped path (e.g. `PoolFactory::address(...)`).
"""

from __future__ import annotations

from _util import (
    functions_in_contractimpl, fn_body, fn_name, is_pub, text_of,
    walk_no_nested_fn, line_col, snippet_of,
)


def _param_names(fn, source: bytes) -> set[str]:
    names = set()
    for c in fn.children:
        if c.type != "parameters":
            continue
        for p in c.children:
            if p.type != "parameter":
                continue
            # parameter → pattern (identifier) : type
            for pp in p.children:
                if pp.type == "identifier":
                    names.add(text_of(pp, source))
                    break
    return names


def _addr_params(fn, source: bytes) -> set[str]:
    names = set()
    for c in fn.children:
        if c.type != "parameters":
            continue
        for p in c.children:
            if p.type != "parameter":
                continue
            ptext = text_of(p, source)
            if "Address" not in ptext:
                continue
            for pp in p.children:
                if pp.type == "identifier":
                    names.add(text_of(pp, source))
                    break
    return names


def _find_invoke(body, source: bytes):
    """Yield (call_node, args_text) for each invoke_contract call."""
    for n in walk_no_nested_fn(body):
        if n.type != "call_expression":
            continue
        t = text_of(n, source)
        if "invoke_contract" in t or "try_invoke_contract" in t:
            yield n, t


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        if not is_pub(fn, source):
            continue
        body = fn_body(fn)
        if body is None:
            continue

        addr_params = _addr_params(fn, source)
        all_params = _param_names(fn, source)
        if not addr_params:
            continue

        for node, ctext in _find_invoke(body, source):
            # Pull out arguments substring after the method name
            # Simple heuristic: the call text has (..., target, symbol, args)
            # We check whether any Address param name appears and at least
            # one other param (for symbol/args).
            addr_used = any(a in ctext for a in addr_params)
            other_param_used = any(
                p in ctext for p in (all_params - addr_params)
            )
            if not (addr_used and other_param_used):
                continue
            # Filter: if the call also contains an explicit known-safe
            # symbol (e.g. hardcoded Symbol::new(&env, "...") with literal),
            # but args still come from params — still a bug. We keep it.
            name = fn_name(fn, source)
            line, col = line_col(node)
            hits.append({
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(node, source),
                "message": (
                    f"pub fn `{name}` forwards `invoke_contract` with "
                    f"caller-controlled target and payload — arbitrary "
                    f"external call (treasury-drain class)."
                ),
            })
    return hits

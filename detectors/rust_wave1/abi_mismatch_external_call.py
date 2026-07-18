"""
abi_mismatch_external_call.py

Flags ONLY high-confidence mismatches between an `env.invoke_contract(addr, symbol, args)`
call and a trait / contract function defined in the SAME crate.

Tightening (v2, 2026-04):
  - `env.invoke_contract(...)` is K2's standard cross-contract call idiom; flagging
    every usage is pure noise (39 hits on K2 baseline).
  - We now only flag two high-confidence cases:
       (a) symbol text matches a function name defined in a `pub trait` or
           `#[contractimpl]` block in the SAME crate, AND the arg list length
           differs from that function's declared parameter count (minus 1 for
           `env: Env`).
       (b) `symbol_short!("typo")` where "typo" is a near-miss against a small
           whitelist of common soroban-sdk method names (transfer, balance,
           allowance, approve, mint, burn, decimals, name, symbol).
  - Everything else is silently dropped.  If no high-confidence finding is
    possible we emit zero hits (the detector is NOT informational — it
    survives only as a high-signal check).

Halborn §7.13, §7.14.
"""

from __future__ import annotations

import re

from _util import walk, text_of, line_col, snippet_of


# Known soroban-sdk / SEP-41 token method names we check typos against.
_KNOWN_SDK_METHODS = {
    "transfer", "transfer_from", "balance", "allowance", "approve",
    "mint", "burn", "burn_from", "decimals", "name", "symbol",
    "authorized", "set_authorized", "set_admin", "clawback",
}


def _symbol_text_from_arg(arg_node, source: bytes) -> str | None:
    """If `arg_node` is `Symbol::new(&env, "xxx")` or `symbol_short!("xxx")`,
    return "xxx".  Otherwise None."""
    t = text_of(arg_node, source)
    # symbol_short!("name") or symbol_short! ( "name" )
    m = re.search(r'symbol_short!\s*\(\s*"([A-Za-z_][A-Za-z0-9_]*)"\s*\)', t)
    if m:
        return m.group(1)
    m = re.search(r'Symbol::new\s*\([^,]+,\s*"([A-Za-z_][A-Za-z0-9_]*)"\s*\)', t)
    if m:
        return m.group(1)
    return None


def _collect_local_fn_names(root, source: bytes) -> dict[str, int]:
    """Collect {fn_name: declared_arity} for every pub fn inside a
    `#[contractimpl]` impl block or a `pub trait` in this file.  Arity excludes
    a leading `env: Env` / `e: Env` parameter (since invoke_contract injects env)."""
    out: dict[str, int] = {}
    for impl in [n for n in walk(root) if n.type == "impl_item"]:
        # Look for preceding #[contractimpl]
        has_contractimpl = False
        prev = impl.prev_named_sibling
        while prev is not None and prev.type == "attribute_item":
            if "contractimpl" in text_of(prev, source):
                has_contractimpl = True
                break
            prev = prev.prev_named_sibling
        if not has_contractimpl:
            continue
        for c in impl.children:
            if c.type != "declaration_list":
                continue
            for d in c.children:
                if d.type != "function_item":
                    continue
                name, arity = _fn_name_and_arity(d, source)
                if name is not None:
                    out[name] = arity
    # Also pub trait declarations
    for n in walk(root):
        if n.type != "trait_item":
            continue
        for c in n.children:
            if c.type != "declaration_list":
                continue
            for d in c.children:
                if d.type == "function_signature_item" or d.type == "function_item":
                    name, arity = _fn_name_and_arity(d, source)
                    if name is not None:
                        out[name] = arity
    return out


def _fn_name_and_arity(fn_node, source: bytes) -> tuple[str | None, int]:
    name = None
    arity = 0
    for c in fn_node.children:
        if c.type == "identifier":
            name = text_of(c, source)
        if c.type == "parameters":
            # Count non-self, non-env params
            for p in c.children:
                if p.type == "parameter":
                    pt = text_of(p, source)
                    # skip env/e: Env receiver
                    if re.match(r'^\s*(env|e)\s*:\s*Env', pt):
                        continue
                    arity += 1
                if p.type == "self_parameter":
                    # methods don't count self
                    continue
    return name, arity


def _count_arglist_elems(arglist_node, source: bytes) -> int:
    """Count the number of `vec![...]` / `Vec::from_array` elements in the
    `args` position of invoke_contract.  Returns -1 if we cannot determine."""
    t = text_of(arglist_node, source)
    # Pattern: vec![&env, a, b, c] — count commas after the env placeholder
    m = re.search(r'vec!\s*\[\s*&?e(?:nv)?\s*,\s*([^\]]*?)\]', t)
    if m:
        inside = m.group(1).strip()
        if not inside:
            return 0
        # Split by commas at depth 0 — simple heuristic
        depth = 0
        elems = 1
        for ch in inside:
            if ch in '([{<':
                depth += 1
            elif ch in ')]}>':
                depth -= 1
            elif ch == ',' and depth == 0:
                elems += 1
        return elems
    # Pattern: Vec::from_array(&env, [a, b, c]) — count commas in brackets
    m = re.search(r'from_array\s*\([^,]+,\s*\[([^\]]*)\]', t)
    if m:
        inside = m.group(1).strip()
        if not inside:
            return 0
        return inside.count(',') + 1
    return -1


def run(tree, source: bytes, filepath: str):
    hits = []
    local_fns = _collect_local_fn_names(tree.root_node, source)

    for n in walk(tree.root_node):
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
        if method not in ("invoke_contract", "try_invoke_contract"):
            continue

        # Get argument list: (addr, symbol, args)
        arg_list = None
        for c in n.children:
            if c.type == "arguments":
                arg_list = c
                break
        if arg_list is None:
            continue
        arg_children = [c for c in arg_list.children
                        if c.type not in ("(", ")", ",")]
        if len(arg_children) < 2:
            continue

        symbol_arg = arg_children[1]
        args_arg = arg_children[2] if len(arg_children) > 2 else None

        sym_name = _symbol_text_from_arg(symbol_arg, source)
        if sym_name is None:
            # stringly-typed but we can't extract the name — skip (too noisy)
            continue

        # Case (a): same-crate name collision + arity mismatch
        if sym_name in local_fns and args_arg is not None:
            expected = local_fns[sym_name]
            actual = _count_arglist_elems(args_arg, source)
            if actual >= 0 and actual != expected:
                line, col = line_col(n)
                hits.append({
                    "severity": "med",
                    "line": line,
                    "col": col,
                    "snippet": snippet_of(n, source),
                    "message": (f"`invoke_contract(\"{sym_name}\", ...)` passes "
                                f"{actual} args but same-crate `{sym_name}` "
                                f"declares {expected} params (Halborn §7.13)."),
                })
                continue

        # Case (b): near-miss typo of a well-known SDK method
        if sym_name not in _KNOWN_SDK_METHODS:
            for known in _KNOWN_SDK_METHODS:
                # Levenshtein distance 1
                if _lev1(sym_name, known):
                    line, col = line_col(n)
                    hits.append({
                        "severity": "med",
                        "line": line,
                        "col": col,
                        "snippet": snippet_of(n, source),
                        "message": (f"`invoke_contract(\"{sym_name}\", ...)` — "
                                    f"likely typo of SDK method `{known}` "
                                    f"(Halborn §7.14)."),
                    })
                    break
    return hits


def _lev1(a: str, b: str) -> bool:
    """True iff the Levenshtein distance between a and b is exactly 1."""
    if a == b:
        return False
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:
        diffs = sum(1 for x, y in zip(a, b) if x != y)
        return diffs == 1
    # insertion/deletion
    short, long = (a, b) if la < lb else (b, a)
    i = j = 0
    found = False
    while i < len(short) and j < len(long):
        if short[i] != long[j]:
            if found:
                return False
            found = True
            j += 1
        else:
            i += 1
            j += 1
    return True

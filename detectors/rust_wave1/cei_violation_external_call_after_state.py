"""
cei_violation_external_call_after_state.py

Flags functions that make an external call AFTER a storage write in the same
function body — a classic Checks-Effects-Interactions violation that opens
the door to reentrancy-style races if the callee ever re-enters the protocol.

Maps to wave3 `reentrancy_state` class ported to Soroban.

External call shapes detected:
  - `env.invoke_contract(...)` / `try_invoke_contract(...)`
  - `<XxxClient>::new(env, addr).<method>(...)`
  - `<XxxClient>::new(&env, &addr).<method>(...)`
  - `token::Client::new(...).<method>(...)` (alias form)

Storage writes detected:
  - `env.storage().persistent()/temporary()/instance().set(...)` (and update/remove)

Heuristic:
  - Order-sensitive: we walk body statements in source order.  A function is
    flagged if an external call appears at a greater `start_byte` than the
    first storage-mutating call.
  - Read-only views (no storage write) are not flagged.
"""

from __future__ import annotations

import re

import pathlib as _pathlib

from _util import (
    functions_in_contractimpl, fn_body, fn_name, is_pub, text_of,
    walk_no_nested_fn, line_col, snippet_of,
    crate_name_from_path, fn_module_path, fn_signature_normalized,
)


_MUT_METHODS = {"set", "update", "remove", "extend_ttl",
                "extend_instance_ttl"}


def _is_storage_mutation(call_node, source):
    callee = None
    for c in call_node.children:
        if c.type == "field_expression":
            callee = c
            break
    if callee is None:
        return False
    method = None
    for c in callee.children:
        if c.type == "field_identifier":
            method = text_of(c, source)
    if method not in _MUT_METHODS:
        return False
    ctxt = text_of(callee, source)
    return ("storage()" in ctxt or ".persistent()" in ctxt
            or ".instance()" in ctxt or ".temporary()" in ctxt)


def _is_external_call(call_node, source):
    """invoke_contract / <Client>::new(...).<method>(...) pattern."""
    callee = None
    for c in call_node.children:
        if c.type in ("field_expression", "generic_function"):
            callee = c
            break
    if callee is None:
        return False
    # For generic_function, descend to its inner field_expression.
    if callee.type == "generic_function":
        inner = None
        for c in callee.children:
            if c.type == "field_expression":
                inner = c
                break
        if inner is not None:
            callee = inner
        else:
            ctxt = text_of(callee, source)
            if "invoke_contract" in ctxt or "try_invoke_contract" in ctxt:
                return True
            return False
    method = None
    for c in callee.children:
        if c.type == "field_identifier":
            method = text_of(c, source)
    if method in ("invoke_contract", "try_invoke_contract"):
        return True
    # <Client>::new(env, addr).<method>(args)
    ctxt = text_of(callee, source)
    if re.search(r'[A-Za-z_][A-Za-z0-9_]*Client\s*::\s*new\s*\(', ctxt):
        return True
    # token::Client::new form
    if re.search(r'::Client\s*::\s*new\s*\(', ctxt):
        return True
    return False


def run(tree, source: bytes, filepath: str):
    hits = []
    root = tree.root_node
    fp = _pathlib.Path(filepath)
    for fn, _impl in functions_in_contractimpl(root, source):
        if not is_pub(fn, source):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        first_mut = None
        external_after_mut = None
        for n in walk_no_nested_fn(body):
            if n.type != "call_expression":
                continue
            if first_mut is None and _is_storage_mutation(n, source):
                first_mut = n
                continue
            if first_mut is not None and _is_external_call(n, source):
                # Ensure physically after the mutation in source order
                if n.start_byte > first_mut.end_byte:
                    external_after_mut = n
                    break
        if first_mut is None or external_after_mut is None:
            continue
        line, col = line_col(external_after_mut)

        # --- Track K-Rust step 1: per-function emit fields ---
        row: dict = {
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(external_after_mut, source),
            "message": (f"CEI violation in `{fn_name(fn, source)}`: external "
                        f"call at line {line} runs AFTER storage write at "
                        f"line {first_mut.start_point[0]+1}. Move the call "
                        f"before the state mutation or add a reentrancy guard."),
        }
        # Optional per-function fields — omit if unknown/empty (backward compat)
        try:
            _crate = crate_name_from_path(fp)
            if _crate and _crate != "unknown":
                row["crate_name"] = _crate
        except Exception:
            pass
        try:
            _mod = fn_module_path(fn, source, fp)
            if _mod:
                row["module_path"] = _mod
        except Exception:
            pass
        try:
            _sig = fn_signature_normalized(fn, source)
            if _sig:
                row["fn_signature"] = _sig
        except Exception:
            pass

        hits.append(row)
    return hits

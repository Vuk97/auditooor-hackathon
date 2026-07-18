"""
delegatecall_to_user_address.py

Soroban has no `delegatecall`, but the closest bug class is:
  - A contract makes a SAC / token transfer-style call where the *contract
    address being invoked* is a parameter supplied by the caller.
  - Specifically dangerous for token `transfer_from(contract_address, ...)`
    patterns where an attacker can pass a fake SEP-41 token whose
    `transfer_from` is a no-op → contract credits the user shares without
    any real inflow ("transfer-to-self bypass").

Heuristic:
  1. pub fn inside #[contractimpl]
  2. body constructs a `TokenClient::new(&env, &X)` (or `sep41::Client`,
     `token::Client`) where `X` is a parameter of type Address.
  3. body then calls `.transfer(...)` / `.transfer_from(...)` on that client.
  4. body has NO call to validate that address against a whitelist
     (`assert_allowed_token`, `validate_asset`, `is_listed`, `reserves`,
     `get_reserve`, `asset_registry`).

This is the Soroban analog of "delegatecall to attacker contract".
"""

from __future__ import annotations

import re

from _util import (
    functions_in_contractimpl, fn_body, fn_name, is_pub, text_of,
    walk_no_nested_fn, line_col, snippet_of,
)


_CLIENT_PATTERNS = [
    r"TokenClient\s*::\s*new\s*\(",
    r"token\s*::\s*Client\s*::\s*new\s*\(",
    r"sep41\s*::\s*Client\s*::\s*new\s*\(",
    r"StellarAssetClient\s*::\s*new\s*\(",
]

_TRANSFER_METHODS = (
    "transfer", "transfer_from", "burn", "mint", "burn_from",
)

_VALIDATION_HINTS = [
    "assert_allowed_token", "validate_asset", "is_listed",
    "get_reserve", "asset_registry", "require_listed",
    "check_reserve", "has_reserve", "whitelist",
]


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


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        if not is_pub(fn, source):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_text = text_of(body, source)

        addr_params = _addr_params(fn, source)
        if not addr_params:
            continue

        # Validation present? skip.
        if any(h in body_text for h in _VALIDATION_HINTS):
            continue

        # Find a TokenClient::new(&env, &<addr_param>) + transfer call
        client_call = None
        for n in walk_no_nested_fn(body):
            if n.type != "call_expression":
                continue
            t = text_of(n, source)
            if not any(re.search(p, t) for p in _CLIENT_PATTERNS):
                continue
            if not any(
                f"&{ap}" in t or f", {ap})" in t or f", {ap} " in t
                for ap in addr_params
            ):
                continue
            client_call = n
            break

        if client_call is None:
            continue

        # Need a transfer/burn/mint call somewhere in body
        has_transfer = False
        for n in walk_no_nested_fn(body):
            if n.type != "call_expression":
                continue
            t = text_of(n, source)
            for m in _TRANSFER_METHODS:
                if re.search(r"\." + m + r"\s*\(", t):
                    has_transfer = True
                    break
            if has_transfer:
                break
        if not has_transfer:
            continue

        name = fn_name(fn, source)
        line, col = line_col(client_call)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(client_call, source),
            "message": (
                f"pub fn `{name}` builds a token Client from a caller-"
                f"controlled Address parameter without whitelist validation "
                f"(delegatecall-analog: attacker plugs in a rogue SEP-41 "
                f"whose transfer is a no-op)."
            ),
        })
    return hits

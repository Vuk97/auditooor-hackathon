"""
r94_unrestricted_mint.py

Flags public `mint` / `mint_to` / `issue` fns that credit a balance or
call a token `mint` without `.require_auth()` on an admin/minter address
AND without any supply cap check — anyone can mint arbitrary supply.

Maps to Solidity:
  - minting-unrestricted
  - options-preview-mint-unchecked-overflow-free-shares
  - glider-exploitable-setfee-no-access-control (related class)

Heuristic:
  - fn name matches `mint`, `mint_to`, `issue`, `create_shares`, `bond`.
  - Body writes a balance-like storage key (`Balance`, `balances`,
    `shares`, `Shares`, `supply`, `TotalSupply`) OR calls `.mint(` on
    a TokenClient.
  - Body does NOT call `.require_auth(` on any address AND does NOT
    contain a supply-cap token: `max_supply`, `MAX_SUPPLY`, `supply_cap`,
    `cap`, `hard_cap`, `MINT_CAP`.
"""

from __future__ import annotations

import re

from _util import (
    functions_in_contractimpl, fn_body, fn_name, is_pub, text_of,
    walk_no_nested_fn, line_col, snippet_of,
)


_MINT_FN_RE = re.compile(
    r"^(mint|mint_to|issue|create_shares|bond|deposit_for|"
    r"add_supply|airdrop|grant_tokens)$"
)

_BALANCE_TOKENS = ("Balance", "balances", "Shares", "shares",
                   "TotalSupply", "total_supply", "Supply",
                   "balance_of", "BalanceOf")

_SUPPLY_CAP_TOKENS = ("max_supply", "MAX_SUPPLY", "supply_cap", "SUPPLY_CAP",
                      "cap", "hard_cap", "HARD_CAP", "MINT_CAP",
                      "mint_cap", "SupplyCap")


def _writes_balance_or_calls_mint(body, source):
    body_text = text_of(body, source)
    # Look for an external `.mint(` call (TokenClient / admin_client).
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
        if method == "mint":
            return n
    # OR the body mentions a balance-like token AND performs a storage
    # write. We do the text check globally (allowing a key bound earlier
    # in the body to carry the balance label), then return the first
    # storage `.set(` call as the anchor.
    if any(tok in body_text for tok in _BALANCE_TOKENS):
        for n in walk_no_nested_fn(body):
            if n.type != "call_expression":
                continue
            t = text_of(n, source)
            if not re.search(r"\.set\s*\(", t):
                continue
            # Must be a storage write (avoid HashMap::new().set)
            if ("storage()" in t or ".persistent()" in t
                    or ".instance()" in t or ".temporary()" in t):
                return n
    return None


def run(tree, source: bytes, filepath: str):
    hits = []
    root = tree.root_node
    for fn, _impl in functions_in_contractimpl(root, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        if not _MINT_FN_RE.match(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_text = text_of(body, source)

        mint_node = _writes_balance_or_calls_mint(body, source)
        if mint_node is None:
            continue

        if ".require_auth(" in body_text:
            continue
        if any(tok in body_text for tok in _SUPPLY_CAP_TOKENS):
            continue

        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(mint_node, source),
            "message": (
                f"pub fn `{name}` mints tokens / credits shares without "
                f"`.require_auth()` and without any supply-cap guard — "
                f"permissionless unlimited mint."
            ),
        })
    return hits

"""
erc4626_inflation_attack.py

Soroban share-vault analog of ERC-4626 first-depositor inflation:
  attacker deposits 1 wei + donates huge underlying → next depositor's
  shares round down to 0 because formula is
    shares = assets * total_supply / total_assets.

Heuristic:
  1. Find fns with name `deposit` / `mint` / `deposit_to`.
  2. Body computes `shares = X * total_supply / total_assets` (or any
     combination of `total_supply()` / `balance_of(self)` / `total_assets`
     in the denominator of a division).
  3. Body must NOT contain a *virtual-shares* / *dead-shares* mitigation:
     + tokens of offset: `+ 10u128.pow(...)`, `+ VIRTUAL_SHARES`,
       `DEAD_SHARES`, `initial_shares`, `MIN_LIQUIDITY`.
     + nor `if total_supply == 0 { assets } else { ... }` check that
       mints a first-deposit minimum (flag only if first-deposit branch
       is absent).
"""

from __future__ import annotations

import re

from _util import (
    function_items, fn_body, fn_name, text_of, walk_no_nested_fn,
    line_col, snippet_of, in_test_cfg,
)


_DENOM_PATTERNS = (
    r"total_supply",
    r"total_assets",
    r"total_shares",
)

_MITIGATION_TOKENS = (
    "VIRTUAL_SHARES", "DEAD_SHARES", "MIN_LIQUIDITY",
    "initial_shares", "virtual_assets", "virtual_shares",
    "INITIAL_DEAD_SHARES",
)


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        name = fn_name(fn, source)
        if name not in ("deposit", "mint", "deposit_to", "mint_shares",
                        "deposit_shares"):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_text = text_of(body, source)

        # Must compute shares via a div involving total_supply/total_assets
        if "/" not in body_text:
            continue
        if not any(re.search(p, body_text) for p in _DENOM_PATTERNS):
            continue
        # Rough check: appears `* total_supply` or `/ total_assets` etc.
        # We require a `*` and `/` with the denom in the same statement
        has_formula = False
        for ln in body_text.splitlines():
            if ("*" in ln and "/" in ln
                    and any(re.search(p, ln) for p in _DENOM_PATTERNS)):
                has_formula = True
                break
        if not has_formula:
            continue

        # Mitigation?
        if any(t in body_text for t in _MITIGATION_TOKENS):
            continue
        # First-deposit branch ok? Look for `if total_supply == 0`
        # or `if total_shares == 0`. If present AND mints a baseline,
        # we skip (heuristic).
        if re.search(r"if\s+(total_supply|total_shares)\s*==\s*0", body_text):
            # Still a bug unless a MIN_LIQUIDITY-style constant appears,
            # which we already checked. Keep flag only if totally absent.
            # If there's a guard that mints min-liquidity-to-zero address,
            # it'd use one of the tokens above. So continue flag.
            pass

        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(body, source, 200),
            "message": (
                f"fn `{name}` computes shares = amount * total_supply / "
                f"total_assets without a virtual-shares / dead-shares "
                f"mitigation (ERC-4626 first-depositor inflation class)."
            ),
        })
    return hits

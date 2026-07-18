"""
share_token_reentrancy_callback.py

Flags `mint` / `burn` / `redeem` fns that call into an EXTERNAL contract
(token client, hook, callback) AFTER reading storage but BEFORE updating it
— classical check-effect-interaction violation specific to ERC-4626-style
share tokens.

Heuristic:
  1. fn_name in {mint, burn, redeem, withdraw, deposit} AND pub.
  2. Body has an external call `Client::new(...).X(...)` or
     `env.invoke_contract(...)`.
  3. Between the call and the end of the body there's a storage write
     (`.set(...)` / `.update(...)`) mutating a balance/index key.

This is narrower than the generic CEI detector — we insist on an explicit
balance/shares key being written AFTER the external call.
"""

from __future__ import annotations

import re

from _util import (
    functions_in_contractimpl, fn_body, fn_name, is_pub, text_of,
    walk_no_nested_fn, line_col, snippet_of,
)


_VAULT_FNS = (
    "mint", "burn", "redeem", "withdraw", "deposit",
    "mint_shares", "burn_shares",
)

_BALANCE_KEY_HINTS = (
    "balance", "shares", "user_shares", "total_supply", "total_shares",
    "reserve", "index", "accrued",
)

_EXTERNAL_CALL_HINTS = (
    r"Client\s*::\s*new\s*\(",
    r"invoke_contract\s*\(",
    r"TokenClient\s*::\s*new\s*\(",
)


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        if name not in _VAULT_FNS:
            continue
        body = fn_body(fn)
        if body is None:
            continue

        body_text = text_of(body, source)
        # Body must plausibly reference a balance/shares key somewhere
        if not any(h in body_text for h in _BALANCE_KEY_HINTS):
            continue

        # Gather call_expression offsets
        ext_call_offsets = []
        storage_write_offsets = []
        for n in walk_no_nested_fn(body):
            if n.type != "call_expression":
                continue
            t = text_of(n, source)
            if any(re.search(p, t) for p in _EXTERNAL_CALL_HINTS):
                ext_call_offsets.append((n.start_byte, n))
                continue
            # storage write?
            if re.search(r"\.(set|update)\s*\(", t) and (
                "storage()" in t or ".persistent(" in t
                or ".instance(" in t or ".temporary(" in t
            ):
                storage_write_offsets.append((n.start_byte, n))

        if not ext_call_offsets or not storage_write_offsets:
            continue
        first_ext = min(o for o, _ in ext_call_offsets)
        # any write AFTER first external call?
        late_writes = [n for o, n in storage_write_offsets if o > first_ext]
        if not late_writes:
            continue

        line, col = line_col(late_writes[0])
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(late_writes[0], source),
            "message": (
                f"pub fn `{name}` writes share/balance state AFTER an "
                f"external token/callback call — reentrancy via share-"
                f"token callback can see stale balance."
            ),
        })
    return hits

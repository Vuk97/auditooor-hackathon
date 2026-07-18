"""
r94_loop_caller_supplied_from_passed_to_mutator_no_auth.py

Flags Soroban-style public functions that accept a caller-supplied
`from` / `owner` / `account` / `user` / `holder` address and forward it
into a state-changing mutator without binding that address to the
authenticated actor.

Target shape:
  - Public contractimpl fn.
  - Body forwards `from` / `owner` / `account` / `user` / `holder` into a
    state-changing helper such as `transfer_from`, `burn_from`,
    `spend_allowance`, `withdraw_from`, `claim_for`, `cancel_for`, or
    `set_delegate`.
  - Body does NOT call `<addr>.require_auth()` and does NOT bind
    `env.invoker()` to that supplied address.

This is a narrow cross-language lift of arbitrary-sender /
authorization-origin misses: privileged effects stay reachable through a
caller-shaped address parameter instead of the authenticated actor.
"""

from __future__ import annotations

import re

from _util import (
    IDENT,
    body_text_nocomment,
    fn_body,
    fn_name,
    functions_in_contractimpl,
    is_pub,
    line_col,
    snippet_of,
)


_PARAM_NAMES = r"(from|owner|account|user|holder)"

_MUTATOR_RE = re.compile(
    fr"(?ix)"
    fr"(?:"
    fr"\b(?:transfer_from|burn_from|spend_allowance|withdraw_from|"
    fr"claim_for|cancel_for|set_delegate|set_approval_for_all|"
    fr"approve_for|redeem_for|debit)\s*\(\s*(?:[^,\n]+,\s*)?&?\s*"
    fr"{IDENT}{_PARAM_NAMES}\b|"
    fr"\.(?:insert|set)\s*\(\s*&?\s*{IDENT}{_PARAM_NAMES}\b"
    fr")"
)

_AUTH_RE = re.compile(
    fr"(?ix)"
    fr"(?:"
    fr"\b{_PARAM_NAMES}\s*\.\s*require_auth\s*\(\s*\)|"
    fr"assert(?:_eq)?!\s*\(\s*env\.invoker\s*\(\s*\)\s*,\s*&?\s*{_PARAM_NAMES}\b|"
    fr"assert(?:_eq)?!\s*\(\s*&?\s*{_PARAM_NAMES}\b\s*,\s*env\.invoker\s*\(\s*\)\s*\)|"
    fr"env\.invoker\s*\(\s*\)\s*==\s*&?\s*{_PARAM_NAMES}\b|"
    fr"&?\s*{_PARAM_NAMES}\b\s*==\s*env\.invoker\s*\(\s*\)"
    fr")"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        if not is_pub(fn, source):
            continue
        body = fn_body(fn)
        if body is None:
            continue

        body_nc = body_text_nocomment(body, source)
        if not _MUTATOR_RE.search(body_nc):
            continue
        if _AUTH_RE.search(body_nc):
            continue

        name = fn_name(fn, source)
        line, col = line_col(fn)
        hits.append(
            {
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:220],
                "message": (
                    f"pub fn `{name}` forwards a caller-supplied "
                    f"`from`/`owner`/`account` address into a "
                    f"state-changing mutator without `require_auth()` "
                    f"or an `env.invoker()` bind - arbitrary-sender "
                    f"state mutation remains reachable."
                ),
            }
        )
    return hits

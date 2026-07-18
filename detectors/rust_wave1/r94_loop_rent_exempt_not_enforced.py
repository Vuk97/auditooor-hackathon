"""
r94_loop_rent_exempt_not_enforced.py

Flags Solana account-creation paths that call `system_instruction::create_account`
(or equivalent) without supplying at-least-rent-exempt lamports (usually
via `Rent::get()?.minimum_balance(space)`).

Source: Solana best-practice; multiple OtterSec findings.
Class: rent-exempt-lifecycle (rust_only).
"""

from __future__ import annotations

import re

from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)


_CREATE_ACCOUNT_RE = re.compile(
    r"system_instruction::create_account\s*\(|"
    r"create_account_checked\s*\(|"
    r"invoke\s*\(\s*&system_instruction::create_account|"
    r"\.create_account\s*\("
)

_RENT_EXEMPT_RE = re.compile(
    r"Rent::get\s*\(\s*\)\.\?\.minimum_balance\s*\(|"
    r"\.minimum_balance\s*\(\s*\w|"
    r"rent_exempt_reserve|rent\.minimum_balance|"
    r"rent_exempt_lamports"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    root = tree.root_node
    for fn, _impl in functions_in_contractimpl(root, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)

        if not _CREATE_ACCOUNT_RE.search(body_nc):
            continue
        if _RENT_EXEMPT_RE.search(body_nc):
            continue

        line, col = line_col(fn)
        hits.append({
            "severity": "medium",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` creates an account without supplying "
                f"rent-exempt lamports (no `Rent::get()?.minimum_balance(...)` "
                f"or `.minimum_balance(...)` call). Account becomes rent-"
                f"collected and returns to the system program, where an "
                f"attacker can re-claim / re-init it."
            ),
        })
    return hits

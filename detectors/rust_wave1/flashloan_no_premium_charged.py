"""
flashloan_no_premium_charged.py

Flags flash-loan entrypoints that transfer tokens out and back in but do NOT
accrue a premium/fee to the protocol.

Heuristic:
  1. Function whose name contains `flash_loan` / `flashloan` /
     `execute_operation` AND is pub (or called from a pub entry).
  2. Body transfers (`.transfer(...)`) tokens out to a receiver.
  3. Body must reference a premium/fee term (`premium`, `fee`,
     `flash_loan_premium`, `protocol_fee`, `accrue_`).
  4. If step 3 absent → flag.

A second variant: body references `premium` but never calls `transfer`,
`.set(...)`, or `.accrue(...)` with it — i.e. computed then dropped.
"""

from __future__ import annotations

import re

from _util import (
    function_items, fn_body, fn_name, text_of, walk_no_nested_fn,
    line_col, snippet_of, in_test_cfg,
)


_PREMIUM_TOKENS = (
    "premium", "flash_loan_premium", "protocol_fee",
    "flash_fee", "flashloan_fee",
)

_USED_TOKENS = ("accrue", "transfer", "set", "mint", "+=", ".add")


def _looks_like_flashloan(name: str) -> bool:
    n = name.lower()
    return ("flash_loan" in n or "flashloan" in n
            or n == "execute_operation" or n == "flash")


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        name = fn_name(fn, source)
        if not _looks_like_flashloan(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_text = text_of(body, source)

        # Must reference a transfer-out style call
        if ".transfer(" not in body_text and ".transfer_from(" not in body_text:
            continue

        # Check premium references
        has_premium_ref = any(t in body_text for t in _PREMIUM_TOKENS)
        if not has_premium_ref:
            line, col = line_col(fn)
            hits.append({
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(body, source, 200),
                "message": (
                    f"fn `{name}` transfers tokens as a flash-loan but never "
                    f"references `premium` / `flash_loan_premium` / "
                    f"`protocol_fee` — no fee is charged."
                ),
            })
            continue

        # premium referenced — is it actually consumed?
        # Look for a line combining a premium token with a use token.
        used = False
        # break body into lines cheaply and check co-occurrence
        for ln in body_text.splitlines():
            if any(p in ln for p in _PREMIUM_TOKENS):
                if any(u in ln for u in _USED_TOKENS):
                    used = True
                    break
        if not used:
            line, col = line_col(fn)
            hits.append({
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(body, source, 200),
                "message": (
                    f"fn `{name}` computes a `premium` value but never uses "
                    f"it (no transfer/set/accrue on the same line) — flash "
                    f"premium silently dropped."
                ),
            })
    return hits

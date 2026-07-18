"""
solana_missing_rent_exemption_check.py

Detects Solana handlers that create / initialize an account (or fund it
for long-lived state) without ensuring the account is rent-exempt.

A Solana account that is not rent-exempt is garbage-collected by the
runtime once its lamport balance can no longer cover rent. A program that
allocates state into a non-rent-exempt account risks that state being
silently wiped, which for protocol state (vault, config, position) is a
freeze / loss-of-funds condition.

Anchor's `#[account(init, payer = ..., space = ...)]` funds rent-exemption
automatically; native programs must call `Rent::get()?.minimum_balance(..)`
and fund the account, or check `rent.is_exempt(lamports, data_len)`.

Bug class: MEDIUM (state loss via rent garbage-collection).
Platform:  Solana native programs.
Empirical anchor: Neodyme "rent exemption" checklist item.

Algorithm:
1. Iterate fns.
2. Flag when the body creates/allocates an account
   (`create_account`, `system_instruction::create_account`,
   `allocate`, `invoke...create_account`) with no rent-exemption
   guard (`minimum_balance`, `is_exempt`, `Rent::get`,
   `rent_exempt`, `#[account(init`).
"""

from __future__ import annotations

import re

DETECTOR_ID = "solana_wave1.solana_missing_rent_exemption_check"

_CREATE_ACCOUNT_RE = re.compile(
    r"\b(create_account\s*\(|"
    r"system_instruction\s*::\s*create_account|"
    r"\ballocate\s*\()"
)

_RENT_GUARD_RE = re.compile(
    r"(minimum_balance\s*\(|"
    r"is_exempt\s*\(|"
    r"Rent\s*::\s*get|"
    r"\brent_exempt\b|"
    r"#\[\s*account\s*\([^)]*\binit\b|"
    r"\brequire\w*\s*!\s*\([^)]*rent)",
    re.IGNORECASE,
)

_TEST_NAME_RE = re.compile(r"^(test_|.*_test$)")


def run(engine, filepath: str):
    hits = []
    for fn in engine.functions():
        name = engine.fn_name(fn)
        if not name or name == "?" or _TEST_NAME_RE.match(name):
            continue
        body = engine.fn_body(fn)
        if body is None:
            continue
        fn_text = engine.text(fn)
        body_text = engine.text(body)

        if not _CREATE_ACCOUNT_RE.search(body_text):
            continue
        if _RENT_GUARD_RE.search(fn_text):
            continue

        hits.append({
            "severity": "medium",
            "line": engine.line(fn),
            "col": engine.col(fn),
            "snippet": fn_text.splitlines()[0][:160],
            "message": (
                f"Solana handler `{name}` creates/allocates an account "
                f"without ensuring rent-exemption (no `minimum_balance` / "
                f"`Rent::get` / `is_exempt`). Underfunded state accounts "
                f"are garbage-collected by the runtime, silently wiping "
                f"protocol state. (class: missing-rent-exemption-check)"),
        })
    return hits

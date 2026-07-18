"""
solana_sysvar_account_spoofing.py

Detects Solana handlers that read a sysvar (Clock, Rent, Instructions,
SlotHashes, etc.) from an instruction-supplied `AccountInfo` without
verifying that account's key against the canonical sysvar id.

Sysvars are accounts at well-known fixed addresses. A program that reads
a sysvar by deserializing whatever account was passed in that slot - via
`Clock::from_account_info(acc)` / `Rent::from_account_info(acc)` /
`sysvar::instructions` parsing - and never checks `acc.key` against
`clock::id()` / `rent::id()` / `sysvar::id()` lets an attacker pass a
counterfeit account whose bytes decode to an arbitrary clock / rent /
instruction set. Spoofed `Clock` enables time-lock bypass; spoofed
`Instructions` sysvar defeats CPI-introspection guards.

Safe: `Clock::get()` / `Rent::get()` (syscall, no account), or
`require!(acc.key == &clock::id())` / `sysvar::clock::check_id(acc.key)`.

Bug class: HIGH (time-lock bypass / introspection-guard bypass via
spoofed sysvar).
Platform:  Solana native programs + Anchor manual sysvar handling.
Empirical anchor: OtterSec "sysvar account" canonical class;
                  rust_wave1.r94_loop_cpi_sysvar_unvalidated (sibling).

Algorithm:
1. Iterate fns that read a sysvar from an account
   (`<Sysvar>::from_account_info`, `load_instruction_at_checked` on a
   raw account, `sysvar::instructions::` parsing of an AccountInfo).
2. Flag when the body does NOT pin the sysvar key
   (`::id()` compare, `check_id`, `Sysvar<'info, T>` Anchor type,
   `*::get()` syscall form).
"""

from __future__ import annotations

import re

DETECTOR_ID = "solana_wave1.solana_sysvar_account_spoofing"

_SYSVAR_READ_RE = re.compile(
    r"\b(Clock|Rent|EpochSchedule|Fees|SlotHashes|StakeHistory|"
    r"RecentBlockhashes|Instructions)\s*::\s*from_account_info\s*\("
    r"|sysvar\s*::\s*instructions\s*::"
)

_SYSVAR_PIN_RE = re.compile(
    r"(::\s*id\s*\(\s*\)|"
    r"\bcheck_id\s*\(|"
    r"\bSysvar\s*<|"
    r"\b(Clock|Rent)\s*::\s*get\s*\(|"
    r"\brequire\w*\s*!\s*\([^)]*(sysvar|clock|rent)|"
    r"\bassert_eq!\s*\([^)]*(clock|rent|sysvar))",
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

        if not _SYSVAR_READ_RE.search(body_text):
            continue
        if _SYSVAR_PIN_RE.search(fn_text):
            continue

        hits.append({
            "severity": "high",
            "line": engine.line(fn),
            "col": engine.col(fn),
            "snippet": fn_text.splitlines()[0][:160],
            "message": (
                f"Solana handler `{name}` reads a sysvar from a supplied "
                f"`AccountInfo` without checking the account key against "
                f"the canonical sysvar id (`::id()` / `check_id` / "
                f"`Sysvar<>`). Attacker passes a counterfeit Clock/Rent/"
                f"Instructions account. (class: sysvar-account-spoofing)"),
        })
    return hits

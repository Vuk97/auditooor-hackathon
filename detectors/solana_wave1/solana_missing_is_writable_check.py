"""
solana_missing_is_writable_check.py

Detects Solana native handlers that mutate an account's data or lamports
without first asserting the account was marked writable in the tx.

The Solana runtime rejects writes to accounts not declared writable, but
only at the END of the instruction - and only for the program's own
accounts. A native program that mutates `account.data` / lamports inside
a CPI-bearing or multi-account flow should defensively assert
`account.is_writable` so it fails fast with a clear error rather than
silently relying on runtime rollback (which masks logic bugs and can let
read-only accounts reach a CPI that does mutate them).

Bug class: MEDIUM (logic-confusion / silent no-op on read-only account).
Platform:  Solana native programs.
Empirical anchor: Neodyme "account mutability" checklist item.

Algorithm:
1. Iterate fns whose signature mentions `AccountInfo`.
2. Flag when the body mutates account data/lamports
   (`data.borrow_mut`, `try_borrow_mut_lamports`,
   `**...lamports.borrow_mut()`) with no `.is_writable` assertion.
"""

from __future__ import annotations

import re

DETECTOR_ID = "solana_wave1.solana_missing_is_writable_check"

_MUTATE_RE = re.compile(
    r"\b(data\s*\.\s*borrow_mut|try_borrow_mut_data|"
    r"try_borrow_mut_lamports|lamports\s*\.\s*borrow_mut)\s*\("
)

_WRITABLE_CHECK_RE = re.compile(
    r"(\.\s*is_writable\b|"
    r"\bassert\w*\s*!\s*\([^)]*is_writable|"
    r"\brequire\w*\s*!\s*\([^)]*is_writable)"
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

        if "AccountInfo" not in fn_text:
            continue
        m = _MUTATE_RE.search(body_text)
        if m is None:
            continue
        if _WRITABLE_CHECK_RE.search(fn_text):
            continue

        hits.append({
            "severity": "medium",
            "line": engine.line(fn),
            "col": engine.col(fn),
            "snippet": fn_text.splitlines()[0][:160],
            "message": (
                f"Solana handler `{name}` mutates account data/lamports "
                f"without asserting `account.is_writable`. A read-only "
                f"account reaches a mutation path; rely-on-runtime-rollback "
                f"masks the logic bug. Assert writability up front. "
                f"(class: missing-is-writable-check)"),
        })
    return hits

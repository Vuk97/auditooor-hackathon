"""
solana_missing_owner_check.py

Detects Solana native handlers that deserialize / read an account's data
without first checking that the account is owned by the expected program.

On Solana the program-ownership of an account is the only thing that
guarantees its data layout was written by trusted code. A handler that
borrows `account.data` (or unpacks it) without first comparing
`account.owner` against the program id (or a known program id like the
SPL Token program) can be fed an attacker-controlled account whose bytes
decode to any state the attacker wants.

Anchor's `Account<'info, T>` performs the owner check implicitly; this
detector targets native `AccountInfo` usage where the check is manual.

Bug class: HIGH (account data injection via owner spoofing).
Platform:  Solana native programs.
Empirical anchor: OtterSec absence-of-account-owner-validation class.
Cross-lang sibling: rust_wave1.solana_program_id_check_missing.

Algorithm:
1. Iterate fns whose signature mentions `AccountInfo`.
2. Flag when the body unpacks / borrows account data
   (`try_borrow_data`, `data.borrow`, `unpack`, `try_from_slice`,
   `deserialize`) with no prior `.owner` comparison or
   `check_program_account` / `assert_owned_by` helper.
"""

from __future__ import annotations

import re

DETECTOR_ID = "solana_wave1.solana_missing_owner_check"

_DATA_READ_RE = re.compile(
    r"\b(try_borrow_data|borrow_data|data\s*\.\s*borrow|"
    r"unpack(_unchecked)?|try_from_slice|deserialize)\s*[\(<]"
)

_OWNER_CHECK_RE = re.compile(
    r"(\.\s*owner\s*[=!]=|"
    r"\bcheck_program_account\s*\(|"
    r"\bassert_owned_by\s*\(|"
    r"\bcheck_account_owner\s*\(|"
    r"\brequire\w*\s*!\s*\([^)]*owner)"
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

        # native AccountInfo handler only
        if "AccountInfo" not in fn_text:
            continue

        m = _DATA_READ_RE.search(body_text)
        if m is None:
            continue
        before = body_text[:m.start()]
        if _OWNER_CHECK_RE.search(before):
            continue

        hits.append({
            "severity": "high",
            "line": engine.line(fn),
            "col": engine.col(fn),
            "snippet": fn_text.splitlines()[0][:160],
            "message": (
                f"Solana handler `{name}` reads/deserializes account data "
                f"without first checking `account.owner` against the "
                f"expected program id. Attacker can supply an account owned "
                f"by a malicious program with crafted bytes. "
                f"(class: missing-owner-check)"),
        })
    return hits

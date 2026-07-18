"""
solana_unchecked_cpi_program_id.py

Detects Solana cross-program invocations (CPI) whose target program
account is taken from instruction input and never validated against a
known / expected program id.

A CPI dispatches to whatever program the supplied program-account points
at. If the program id is an unvalidated `AccountInfo` from the
instruction, an attacker substitutes a malicious program that mimics the
expected interface (e.g. a fake "token program") and intercepts the call,
draining funds or forging state transitions.

Safe handlers pin the CPI target: compare against `spl_token::id()`,
`token_program.key == &expected`, `anchor_spl::token::ID`, an Anchor
`Program<'info, Token>` type (self-validates), or an
`assert_eq!(program.key, &EXPECTED_ID)`.

Bug class: HIGH (arbitrary program execution / fund theft via fake CPI
target).
Platform:  Solana native programs + Anchor manual CPI.
Empirical anchor: OtterSec "arbitrary CPI" canonical class;
                  sealevel-attacks arbitrary-cpi.

Algorithm:
1. Iterate fns whose body issues a CPI (`invoke(`, `invoke_signed(`).
2. Flag when the body has no program-id pin
   (`::id()`, `.key == `, `Program<`, `assert_eq!(...program`,
   `require_keys_eq!`, a hard-coded `Pubkey` constant compare).
"""

from __future__ import annotations

import re

DETECTOR_ID = "solana_wave1.solana_unchecked_cpi_program_id"

_CPI_RE = re.compile(r"\b(invoke|invoke_signed)\s*\(")

_PROGRAM_PIN_RE = re.compile(
    r"(::\s*id\s*\(\s*\)|"
    r"\.\s*key\s*\(?\s*\)?\s*==|"
    r"==\s*&?\w*program\w*\.\s*key|"
    r"\bProgram\s*<|"
    r"\bassert_eq!\s*\([^)]*program|"
    r"\brequire_keys_eq!\s*\(|"
    r"\brequire\w*\s*!\s*\([^)]*program_id|"
    r"\bcheck_program_account\s*\()",
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

        if not _CPI_RE.search(body_text):
            continue
        if _PROGRAM_PIN_RE.search(fn_text):
            continue

        hits.append({
            "severity": "high",
            "line": engine.line(fn),
            "col": engine.col(fn),
            "snippet": fn_text.splitlines()[0][:160],
            "message": (
                f"Solana handler `{name}` issues a CPI (`invoke`/"
                f"`invoke_signed`) without pinning the target program id "
                f"to a known program (no `::id()` / `.key ==` / "
                f"`Program<>` check). Attacker substitutes a malicious "
                f"program. (class: unchecked-cpi-program-id)"),
        })
    return hits

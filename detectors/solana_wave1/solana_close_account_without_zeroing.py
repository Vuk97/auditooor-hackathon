"""
solana_close_account_without_zeroing.py

Detects Solana account-close flows that drain an account's lamports but
do not zero / wipe its data, leaving a "revival"-attackable account.

Closing a Solana account means transferring all its lamports out so the
runtime garbage-collects it. But within the SAME transaction, the account
still exists and still holds its old data. If a program closes an account
by only moving lamports - and does not also zero the data buffer, assign
the owner to the System Program, and set the discriminator to a closed
marker - an attacker can, in a follow-up instruction of the same tx,
re-fund the account (top up rent) and the stale data survives. This is
the classic "closed-account revival" vector: a closed vault/position
account is reused with its old (now invalid) state.

Anchor's `#[account(close = recipient)]` does the full safe close
(lamports drain + data wipe + discriminator set to CLOSED). Manual closes
must replicate all of it.

Bug class: HIGH (closed-account revival -> stale-state reuse / double
spend).
Platform:  Solana native programs + Anchor manual close.
Empirical anchor: OtterSec "closing accounts" canonical class;
                  sealevel-attacks closing-accounts.

Algorithm:
1. Iterate fns that perform a close (drain all lamports to a recipient:
   `**...lamports.borrow_mut() = 0`, `try_borrow_mut_lamports`+`= 0`,
   or a fn named `close*`).
2. Flag when the body does NOT also wipe data
   (`data.borrow_mut()...fill(0)`, `sol_memset`, `= &mut []`,
   `CLOSED_ACCOUNT_DISCRIMINATOR`, `#[account(close`).
"""

from __future__ import annotations

import re

DETECTOR_ID = "solana_wave1.solana_close_account_without_zeroing"

# Draining lamports to zero == a close.
_DRAIN_RE = re.compile(
    r"(lamports\s*\.\s*borrow_mut\s*\(\s*\)\s*=?\s*0|"
    r"try_borrow_mut_lamports\s*\(\s*\)[^;]*=\s*0|"
    r"\*\*\s*\w+\.lamports[^;]*=\s*0)"
)

# Data wipe / closed-marker -> safe. A genuine safe close zeroes the data
# buffer, writes a closed discriminator, reassigns ownership to the System
# Program, or reallocs to length 0. These signals are matched anywhere in
# the fn (the `let mut data = acc.data.borrow_mut(); data.fill(0);` idiom
# spans two statements, so signal-level matching is required).
_WIPE_RE = re.compile(
    r"(\bfill\s*\(\s*0\s*\)|"
    r"\bsol_memset\b|"
    r"CLOSED_ACCOUNT_DISCRIMINATOR|"
    r"#\[\s*account\s*\([^)]*\bclose\b|"
    r"\bassign\s*\([^)]*system_program|"
    r"\.\s*realloc\s*\(\s*0)"
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

        named_close = name.lower().startswith("close")
        drains = bool(_DRAIN_RE.search(body_text))
        if not (drains or (named_close and drains)):
            # Require an actual lamport drain; a bare `close`-named fn
            # with no drain is not necessarily a close.
            if not drains:
                continue
        if _WIPE_RE.search(fn_text):
            continue

        hits.append({
            "severity": "high",
            "line": engine.line(fn),
            "col": engine.col(fn),
            "snippet": fn_text.splitlines()[0][:160],
            "message": (
                f"Solana handler `{name}` closes an account by draining "
                f"lamports but never zeroes its data / sets a closed "
                f"discriminator. In-tx revival lets an attacker re-fund "
                f"the account and reuse its stale state. "
                f"(class: close-account-without-zeroing)"),
        })
    return hits

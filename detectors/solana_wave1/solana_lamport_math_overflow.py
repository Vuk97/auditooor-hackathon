"""
solana_lamport_math_overflow.py

Detects unchecked integer arithmetic on lamport / token-amount values in
Solana programs.

Solana programs are compiled in release mode by default, where Rust
integer overflow WRAPS silently rather than panicking. Arithmetic on
lamport balances, token amounts, share counts, or fee values that uses
the bare `+ - *` operators (instead of `checked_add` / `checked_sub` /
`checked_mul` / `saturating_*`) can wrap, letting an attacker mint value
from nothing (overflow) or drain via underflow (`balance - amount` where
`amount > balance` wraps to a huge number).

Bug class: HIGH (value creation / drain via silent wraparound).
Platform:  Solana programs (release-mode overflow-wraps semantics).
Empirical anchor: Neodyme "integer overflow" checklist; sealevel-attacks
                  integer-overflow.

Algorithm:
1. Iterate fns whose body references lamports / amount / balance / shares.
2. Flag a bare arithmetic operator (`+ - *`) applied to such a value
   when the body does NOT use a checked/saturating form for it AND the
   crate does not declare `overflow-checks = true` (best-effort: detector
   cannot see Cargo.toml, so it flags the bare-op shape regardless and
   relies on the negative fixture using checked math).
"""

from __future__ import annotations

import re

DETECTOR_ID = "solana_wave1.solana_lamport_math_overflow"

# A money-typed identifier near an arithmetic op.
_BARE_ARITH_RE = re.compile(
    r"\b\w*(lamports?|amount|balance|shares?|fee|supply|reserve)\w*\b"
    r"\s*(\+|\-|\*)\s*"
    r"(?!=)"                       # not `+=`-style compound on its own line
    r"[\w.]",
    re.IGNORECASE,
)

# Checked / saturating math anywhere -> treat fn as defended.
_CHECKED_RE = re.compile(
    r"\b(checked_add|checked_sub|checked_mul|checked_div|"
    r"saturating_add|saturating_sub|saturating_mul|"
    r"overflowing_add|overflowing_sub)\b"
)

# overflow-checks pragma occasionally inlined in the file header.
_OVERFLOW_PRAGMA_RE = re.compile(r"overflow[-_]checks\s*=\s*true")

_TEST_NAME_RE = re.compile(r"^(test_|.*_test$)")
_LINE_COMMENT_RE = re.compile(r"//[^\n]*")


def run(engine, filepath: str):
    hits = []
    fns = list(engine.functions())

    # Best-effort: if any fn body declares the overflow-checks pragma inline
    # (rare, but some crates put `#![...]` near code), treat the file as
    # overflow-safe. The pragma normally lives in Cargo.toml which the
    # engine cannot see; the negative fixture relies on `checked_*` instead.
    for fn in fns:
        b = engine.fn_body(fn)
        if b is not None and _OVERFLOW_PRAGMA_RE.search(engine.text(b)):
            return hits

    for fn in fns:
        name = engine.fn_name(fn)
        if not name or name == "?" or _TEST_NAME_RE.match(name):
            continue
        body = engine.fn_body(fn)
        if body is None:
            continue
        body_text = _LINE_COMMENT_RE.sub("", engine.text(body))

        if _CHECKED_RE.search(body_text):
            continue
        if not _BARE_ARITH_RE.search(body_text):
            continue

        hits.append({
            "severity": "high",
            "line": engine.line(fn),
            "col": engine.col(fn),
            "snippet": engine.text(fn).splitlines()[0][:160],
            "message": (
                f"Solana handler `{name}` performs bare arithmetic "
                f"(`+`/`-`/`*`) on a lamport/amount/balance/shares value "
                f"with no `checked_*` / `saturating_*` form. Release-mode "
                f"Solana builds wrap on overflow - value can be minted or "
                f"drained. (class: lamport-math-overflow)"),
        })
    return hits

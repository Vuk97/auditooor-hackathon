"""
solana_pda_bump_not_canonical.py

Detects Solana PDA derivations that use an attacker-suppliable bump seed
instead of the canonical bump.

A Program-Derived Address is derived from seeds plus a one-byte bump.
There are typically several valid bumps for a given seed set; the
`canonical` bump is the single highest one returned by
`Pubkey::find_program_address` / Anchor `bump` (no value). If a program
derives a PDA with `create_program_address` while passing a bump taken
from instruction input (or a stored field that was never pinned to the
canonical value), an attacker supplies a DIFFERENT valid bump and derives
a SECOND, distinct PDA for the same logical seeds - bypassing uniqueness
assumptions (one-vault-per-user, one-config, replay guards).

Safe: `find_program_address` (returns canonical bump), Anchor
`#[account(seeds = [...], bump)]` with no explicit value, or storing and
re-checking the canonical bump.

Bug class: HIGH (PDA uniqueness bypass -> duplicate state / replay).
Platform:  Solana native programs + Anchor manual PDA handling.
Empirical anchor: OtterSec "bump seed canonicalization" canonical class;
                  rust_wave1.r94_loop_pda_canonical_bump_missing (sibling).

Algorithm:
1. Iterate fns whose body derives a PDA via `create_program_address`.
2. Flag when the body does NOT also pin canonicity:
   `find_program_address`, an Anchor `bump` attribute with no `= expr`,
   or an explicit canonical-bump comparison.
"""

from __future__ import annotations

import re

DETECTOR_ID = "solana_wave1.solana_pda_bump_not_canonical"

_CREATE_PDA_RE = re.compile(r"\bcreate_program_address\s*\(")

_CANONICAL_RE = re.compile(
    r"(\bfind_program_address\b|"
    r"#\[\s*account\s*\([^)]*\bbump\b(?!\s*=)|"   # `bump` with no `= expr`
    r"\bcanonical_bump\b|"
    r"\bassert_eq!\s*\([^)]*bump|"
    r"\brequire\w*\s*!\s*\([^)]*bump)"
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

        if not _CREATE_PDA_RE.search(body_text):
            continue
        if _CANONICAL_RE.search(fn_text):
            continue

        hits.append({
            "severity": "high",
            "line": engine.line(fn),
            "col": engine.col(fn),
            "snippet": fn_text.splitlines()[0][:160],
            "message": (
                f"Solana handler `{name}` derives a PDA with "
                f"`create_program_address` using a non-canonical bump "
                f"(no `find_program_address` / Anchor `bump` / canonical "
                f"check). Attacker supplies an alternate valid bump and "
                f"derives a duplicate PDA, bypassing uniqueness. "
                f"(class: pda-bump-not-canonical)"),
        })
    return hits

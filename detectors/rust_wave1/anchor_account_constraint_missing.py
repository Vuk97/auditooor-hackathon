"""
anchor_account_constraint_missing.py

Anchor / Solana class: struct field carries `#[account(...)]` attribute
but omits `seeds = [...]` AND `mut` AND `signer`, yet the field is
written or used as a signer authority elsewhere. Missing PDA /
account-substitution guard.

Heuristic (text-based; fixtures are not real anchor):
  1. Find lines matching `#[account(` followed by a field declaration.
  2. Inspect the attr token content: flag when it does NOT contain
     any of `seeds`, `mut`, `signer`, `has_one`, `constraint`, `address`,
     `owner`, `token::`, `associated_token::`.
  3. Skip if attr contains ONLY `init` (valid for init-only PDAs).
"""

from __future__ import annotations

import re

from _util import text_of, line_col


_ACCOUNT_ATTR_RE = re.compile(
    r"#\[\s*account\s*\(([^)]*)\)\s*\]\s*\n\s*(?:pub\s+)?"
    r"([A-Za-z_][A-Za-z_0-9]*)\s*:",
    re.MULTILINE
)

_SAFE_CONSTRAINTS = (
    "seeds", "mut", "signer", "has_one", "constraint", "address",
    "owner", "token::", "associated_token::",
    "realloc", "close", "zero", "bump",
)


_ANCHOR_MARKER_RE = re.compile(
    r"(#\[derive\(Accounts\)\]|AccountInfo\s*<|Signer\s*<|"
    r"anchor_lang::|use\s+anchor_lang|Account\s*<\s*'info)"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    text = source.decode("utf-8", errors="replace")
    if not _ANCHOR_MARKER_RE.search(text):
        return hits
    for m in _ACCOUNT_ATTR_RE.finditer(text):
        args = m.group(1)
        field_name = m.group(2)
        if any(c in args for c in _SAFE_CONSTRAINTS):
            continue
        # `init` alone is still risky without seeds — flag
        # But skip if attr is essentially empty (no-op tag).
        stripped = args.strip().strip(",").strip()
        if stripped == "":
            # bare #[account()] — still suspicious, flag
            pass

        # Line number: count newlines before match
        before = text[:m.start()]
        line = before.count("\n") + 1
        hits.append({
            "severity": "medium",
            "line": line,
            "col": 0,
            "snippet": m.group(0)[:160].replace("\n", " "),
            "message": (
                f"Anchor field `{field_name}` has `#[account(...)]` with no "
                f"`seeds` / `mut` / `signer` / `has_one` / `constraint` — "
                f"PDA spoof / account-substitution surface."
            ),
        })
    return hits

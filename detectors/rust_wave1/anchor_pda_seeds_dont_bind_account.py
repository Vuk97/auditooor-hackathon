"""
anchor_pda_seeds_dont_bind_account.py

Anchor PDA derivation that uses ONLY literal seeds (e.g. `seeds = [b"pool"]`)
instead of binding to a user / authority / token mint. Allows one PDA for
many users — one account's state serves all callers.

Heuristic:
  1. Find `seeds = [ ... ]` attribute argument lists.
  2. Examine seed list text. If it contains ONLY bytestring / string
     literals (e.g. `b"pool"`, `"POOL"`, `POOL_SEED`) AND has no reference
     to `.key()` / `.as_ref()` / `token_mint` / `user` / `authority` /
     `owner` / `bump`, flag it.
"""

from __future__ import annotations

import re

from _util import line_col


_SEEDS_ATTR_RE = re.compile(
    r"seeds\s*=\s*\[\s*([^\]]*)\]", re.MULTILINE
)

_BIND_HINT_TOKENS = (
    ".key()", ".as_ref(", "token_mint", "user", "authority",
    "owner", "payer", "mint", "recipient", "creator",
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
    for m in _SEEDS_ATTR_RE.finditer(text):
        seed_body = m.group(1)
        if any(tok in seed_body for tok in _BIND_HINT_TOKENS):
            continue
        # Only literal seeds → flag
        # Count newlines before match to get line
        before = text[:m.start()]
        line = before.count("\n") + 1
        hits.append({
            "severity": "high",
            "line": line,
            "col": 0,
            "snippet": m.group(0)[:160].replace("\n", " "),
            "message": (
                "Anchor `seeds = [...]` contains only literal byte/string "
                "constants — PDA not bound to any account (user / mint / "
                "authority). One PDA serves all callers."
            ),
        })
    return hits

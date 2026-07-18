"""
r94_loop_pda_canonical_bump_missing.py

Flags Solana `create_program_address` calls that derive a PDA without
first obtaining the canonical bump via `find_program_address`. When
the non-canonical bump is accepted, attacker can grind bumps until
the PDA matches a different program's address — or match an existing
account under a different seed.

Source: Solana best-practice; multiple OtterSec/Zellic findings.
Class: pda-canonical-bump-missing (rust_only).
"""

from __future__ import annotations

import re

from _util import (
    functions_in_contractimpl, fn_body, fn_name, text_of, line_col, snippet_of, is_pub, body_text_nocomment, IDENT,
)


_CREATE_RE = re.compile(r"Pubkey::create_program_address\s*\(")
_CANONICAL_RE = re.compile(
    r"Pubkey::find_program_address\s*\(|"
    fr"canonical_bump|get_canonical_bump|bump\s*=\s*{IDENT}canonical"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    root = tree.root_node
    for fn, _impl in functions_in_contractimpl(root, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)

        if not _CREATE_RE.search(body_nc):
            continue
        if _CANONICAL_RE.search(body_nc):
            continue

        line, col = line_col(fn)
        hits.append({
            "severity": "medium",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` uses `Pubkey::create_program_address` "
                f"WITHOUT `find_program_address` / a canonical-bump "
                f"binding. Non-canonical bumps can be ground to match "
                f"other program addresses or existing accounts."
            ),
        })
    return hits

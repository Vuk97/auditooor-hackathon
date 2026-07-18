"""
r94_loop_pda_seed_collision.py

Flags Solana PDA seed sets where two DIFFERENT business inputs could
hash to the same PDA — i.e. seeds that concatenate variable-length
byte slices without a separator / length prefix.

Source: Solodit Zellic Chainflip Solana #3.2 (potential-seed-collision).
Class: pda-seed-collision (rust_only).

Heuristic:
  1. Body calls `Pubkey::find_program_address` / `create_program_address` /
     `#[account(seeds = [...])]`.
  2. Seeds array contains >= 2 consecutive slices of Variable-length bytes
     (e.g., `user.key().as_ref()`, `name.as_bytes()`, `symbol.as_bytes()`)
     WITHOUT a length prefix or separator tag between them.
"""

from __future__ import annotations

import re

from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)


_PDA_DERIVE_RE = re.compile(
    r"Pubkey::find_program_address\s*\(|"
    r"Pubkey::create_program_address\s*\(|"
    r"seeds\s*=\s*\[|"
    r"seeds\s*=\s*&\s*\["
)

# Two consecutive variable-length byte-slices with no literal separator
# between them in the seeds array.
_COLLIDING_SEEDS_RE = re.compile(
    r"(\w+\.as_bytes\s*\(\s*\)|\w+\.to_le_bytes\s*\(\s*\)|"
    r"\w+\.key\s*\(\s*\)\.as_ref\s*\(\s*\)|"
    r"&\w+\[\.\.\])"
    r"\s*,\s*"
    r"(\w+\.as_bytes\s*\(\s*\)|\w+\.to_le_bytes\s*\(\s*\)|"
    r"\w+\.key\s*\(\s*\)\.as_ref\s*\(\s*\)|"
    r"&\w+\[\.\.\])"
)

# Separator markers: literal bytes like b"_" or prepended length
_SEPARATOR_RE = re.compile(
    r"b\"[^\"]\"|\[\s*\d+\s*\]|\.len\s*\(\)\.to_le_bytes"
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

        if not _PDA_DERIVE_RE.search(body_nc):
            continue
        if not _COLLIDING_SEEDS_RE.search(body_nc):
            continue
        if _SEPARATOR_RE.search(body_nc):
            continue

        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` derives a PDA with ≥ 2 consecutive "
                f"variable-length byte-slices in `seeds` (e.g. "
                f"`name.as_bytes()`, `symbol.as_bytes()`) and no literal "
                f"separator / length-prefix between them. Two distinct "
                f"(name, symbol) pairs can collide on one PDA. "
                f"See Solodit Zellic Chainflip #3.2."
            ),
        })
    return hits

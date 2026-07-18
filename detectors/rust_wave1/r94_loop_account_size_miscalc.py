"""
r94_loop_account_size_miscalc.py

Flags Solana account-creation paths where `space` / `size` arg
differs from the actual serialized struct size (via
`std::mem::size_of::<T>()` / `T::LEN` / `T::SPACE`).

Class: account-size-miscalc (rust_only).
"""

from __future__ import annotations
import re
from _util import (
    source_nocomment,
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)

# Hardcoded literal used as space in create_account/init
_HARDCODED_SIZE_RE = re.compile(
    r"system_instruction::create_account\s*\([^)]*?,\s*(\d{2,5})\s*[,)]|"
    r"#\[account\([^)]*?space\s*=\s*(\d{2,5})"
)

_COMPUTED_SIZE_RE = re.compile(
    r"std::mem::size_of::<\w+>\s*\(\s*\)|"
    r"\w+::LEN\b|\w+::SPACE\b|\w+::SIZE\b|"
    r"DISCRIMINATOR_SIZE\s*\+"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    root = tree.root_node
    src_nc = source_nocomment(source)

    hardcoded = list(_HARDCODED_SIZE_RE.finditer(src_nc))
    if not hardcoded:
        return hits
    if _COMPUTED_SIZE_RE.search(src_nc):
        return hits  # at least one size is computed — heuristic says OK

    for m in hardcoded[:3]:
        prefix = src_nc[:m.start()]
        line = prefix.count("\n") + 1
        hits.append({
            "severity": "medium",
            "line": line,
            "col": 0,
            "snippet": m.group(0)[:120],
            "message": (
                f"hardcoded literal size `{m.group(1) or m.group(2)}` used "
                f"in account allocation. No use of "
                f"`std::mem::size_of::<T>()` / `T::LEN` / `T::SPACE` in "
                f"this file — allocation and serialized struct can drift."
            ),
        })
    return hits

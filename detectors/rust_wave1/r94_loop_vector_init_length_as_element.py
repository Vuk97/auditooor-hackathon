"""
r94_loop_vector_init_length_as_element.py

Flags the Mayan-style bug where a Vec is initialized with ONE element
whose value IS the intended length, instead of `Vec::with_capacity(len)`
+ `resize(...)` or a loop that pushes `len` actual elements.

Source: Solodit #53222 (OtterSec Mayan Solana).
Class: vector-init-length-as-element (rust_only).

Heuristic:
  - `vec![len]`, `vec![some_len]`, `vec![expected_len]`
    where the name `len` appears to have been computed as a length.
  - `= vec![<var>]` where the previous line assigns `<var> = … .len() / … * N`.
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)

# Simpler shape: `vec![<ident>]` where the ident's name contains `len`
# or `size` or `count` — strong heuristic for "length-as-element".
_VEC_INIT_RE = re.compile(
    r"vec!\s*\[\s*(\w*(len|size|count|size_of|length)\w*)\s*\]"
)

# Counterexample: `vec![val; len]` — Rust macro form for "len copies of val"
# is the CORRECT pattern. My regex above with `;` absent ensures we only
# flag the single-element form.


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
        for m in _VEC_INIT_RE.finditer(body_nc):
            line, col = line_col(fn)
            hits.append({
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": m.group(0)[:120],
                "message": (
                    f"pub fn `{name}` initializes a Vec with "
                    f"`{m.group(0)}` — a single element whose value is a "
                    f"length-like variable. Likely intended "
                    f"`vec![default; {m.group(1)}]` or "
                    f"`Vec::with_capacity({m.group(1)})`. Indexing "
                    f"`[1..3]` will panic. See Solodit #53222 (Mayan)."
                ),
            })
            break
    return hits

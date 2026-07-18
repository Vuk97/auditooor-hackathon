"""
r94_loop_double_subtraction_accounting.py

Flags a fn that subtracts the same variable twice from a value.
Classic sibling / deposit-limit breach bug.

Source: Solodit #65263 (Sherlock CurrentSUI).
Class: double-subtraction-accounting (both).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
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

        # Look for repeated `... - <ident> - <ident>` OR sequential `-= <ident>` ... `-= <ident>`
        # with the same ident.
        repeat_hit = re.search(
            r"(?:\w+)\s*-\s*(\w+)\s*-\s*\1\b",
            body_nc,
        )
        if repeat_hit is None:
            repeat_hit = re.search(
                r"(\w+)\s*-=\s*(\w+)[\s\S]{0,200}?\1\s*-=\s*\2",
                body_nc,
            )
        if repeat_hit is None:
            continue
        line, col = line_col(fn)
        field = repeat_hit.group(1) if repeat_hit.groups() else "<field>"
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` subtracts `{field}` twice from the "
                f"same accumulator. Classic double-subtraction — the "
                f"used-cap is understated, attacker bypasses limit. "
                f"See Solodit #65263 (CurrentSUI)."
            ),
        })
    return hits

"""
gas_limit_exhaustion_via_unbounded_loop.py

Flags pub contract fns containing a `for`/`while` loop over a value whose
size is NOT bounded by a constant and NOT checked against a MAX_*
constant.

Heuristic:
  1. pub fn in #[contractimpl].
  2. body has a `for <x> in <iter>` where `<iter>` is one of:
       - a function parameter of type `Vec<_>` or `Map<_,_>`
       - `.iter()` on such a parameter
       - `.storage().persistent().get(...)` returning a Vec/Map
  3. body has NO length-bound check — we look for
     `assert!(<iter>.len() <= MAX_*)` or `if <iter>.len() > X { panic! }`.

Conservative: require at least one Vec/Map parameter (or read from
storage of a Vec-like type) inferred by the loop's iterator containing
a parameter name also typed `Vec<...>`.
"""

from __future__ import annotations

import re

from _util import (
    functions_in_contractimpl, fn_body, fn_name, is_pub, text_of,
    walk_no_nested_fn, line_col, snippet_of,
)


def _vec_like_params(fn, source: bytes) -> set[str]:
    names = set()
    for c in fn.children:
        if c.type != "parameters":
            continue
        for p in c.children:
            if p.type != "parameter":
                continue
            ptext = text_of(p, source)
            if ("Vec<" in ptext or "Map<" in ptext
                    or "Vec <" in ptext):
                for pp in p.children:
                    if pp.type == "identifier":
                        names.add(text_of(pp, source))
                        break
    return names


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        if not is_pub(fn, source):
            continue
        vec_params = _vec_like_params(fn, source)
        if not vec_params:
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_text = text_of(body, source)

        # bound check?
        bound_check = re.search(
            r"assert!\s*\([^)]*\.len\(\)\s*[<>=]",
            body_text
        ) or re.search(
            r"if\s+[^{]*\.len\(\)\s*>\s*\w+[^{]*\{",
            body_text
        ) or re.search(
            r"if\s+[^{]*\.len\(\)\s*>=\s*\w+[^{]*\{",
            body_text
        ) or "MAX_" in body_text
        if bound_check:
            continue

        # find a `for` node whose iter text contains one of the vec
        # params
        target = None
        for n in walk_no_nested_fn(body):
            if n.type != "for_expression":
                continue
            t = text_of(n, source)
            # iter is roughly everything after `in ` up to `{`
            m = re.search(r"\bin\s+([^{]+)\{", t, re.DOTALL)
            if not m:
                continue
            iter_expr = m.group(1)
            if any(re.search(r"\b" + v + r"\b", iter_expr)
                   for v in vec_params):
                target = n
                break
        if target is None:
            continue

        line, col = line_col(target)
        hits.append({
            "severity": "low",
            "line": line,
            "col": col,
            "snippet": snippet_of(target, source),
            "message": (
                f"pub fn `{fn_name(fn, source)}` iterates over a caller-"
                f"supplied Vec/Map without a length bound — Soroban CPU "
                f"budget can be exhausted."
            ),
        })
    return hits

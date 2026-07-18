"""
r94_loop_division_by_zero_on_user_input.py

Flags division operations where the divisor is a user-supplied function
parameter and no explicit `parameter > 0` check precedes the division.

Source: Solodit #55256 (Sherlock / SEDA Protocol).
Rust side of the `division-by-zero` canonical bug class.

Heuristic:
  1. For each pub fn, collect the parameter-names that are numeric types
     (u64 / u128 / i64 / i128 / u32 / usize).
  2. Walk for `binary_expression` nodes with operator `/` or `%`.
  3. If the right operand is (directly) one of the parameter names AND
     no preceding statement in this fn contains
     `param == 0`, `param != 0`, `param > 0`, `require(param > 0)`,
     `panic_with_error! ... zero`, or `if param == 0 { panic ... }`,
     emit a hit.

False-positive avoidance:
  - Skip if the divisor is a constant (literal int), a field access
    (`self.x`), or the result of a function call.
  - Skip if the fn is `#[cfg(test)]` or inside a `mod tests {...}`.
"""

from __future__ import annotations

import re

from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    walk_no_nested_fn, text_of, line_col, snippet_of, is_pub,
)


_NUMERIC_TY_RE = re.compile(r"\b(u8|u16|u32|u64|u128|i8|i16|i32|i64|i128|usize|isize)\b")


def _numeric_param_names(fn, source: bytes) -> list[str]:
    names = []
    params = None
    for c in fn.children:
        if c.type == "parameters":
            params = c
            break
    if params is None:
        return names
    for p in params.children:
        if p.type != "parameter":
            continue
        name, ty = None, None
        for cc in p.children:
            if cc.type == "identifier":
                name = text_of(cc, source)
            if cc.type == "primitive_type":
                ty = text_of(cc, source)
        if name and ty and _NUMERIC_TY_RE.search(ty):
            names.append(name)
    return names


def _binary_div_mod(node):
    if node.type != "binary_expression":
        return None
    for c in node.children:
        if c.type in ("/", "%") or (c.is_named and c.type == "arithmetic_operator"):
            # tree-sitter's operator is typically a non-named anonymous node
            pass
    # Easier: scan raw children tokens
    for idx, c in enumerate(node.children):
        if not c.is_named and c.type in ("/", "%"):
            if idx + 1 < len(node.children):
                return node.children[idx + 1]
    return None


def _has_zero_guard(body_text: str, param: str) -> bool:
    """Any statement before the first division that checks param != 0."""
    patterns = [
        rf"\b{re.escape(param)}\s*==\s*0",
        rf"\b{re.escape(param)}\s*!=\s*0",
        rf"\b{re.escape(param)}\s*>\s*0",
        rf"\b0\s*<\s*{re.escape(param)}\b",
        rf"require\s*\(\s*{re.escape(param)}\s*[>!=]",
        rf"panic_with_error!\s*\([^)]*{re.escape(param)}",
        rf"if\s+{re.escape(param)}\s*==\s*0",
    ]
    for pat in patterns:
        if re.search(pat, body_text):
            return True
    return False


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
        body_text = text_of(body, source)

        params = _numeric_param_names(fn, source)
        if not params:
            continue

        for n in walk_no_nested_fn(body):
            if n.type != "binary_expression":
                continue
            rhs = _binary_div_mod(n)
            if rhs is None:
                continue
            if rhs.type != "identifier":
                continue
            rhs_name = text_of(rhs, source).strip()
            if rhs_name not in params:
                continue
            if _has_zero_guard(body_text, rhs_name):
                continue

            line, col = line_col(n)
            hits.append({
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(n, source),
                "message": (
                    f"fn `{name}` divides (or modulo) by the user-controlled "
                    f"parameter `{rhs_name}` with no `{rhs_name} > 0` guard. "
                    f"Zero input triggers division-by-zero panic — on Solana/"
                    f"Soroban this can halt validator execution or burn "
                    f"compute budget. See Solodit #55256 (SEDA)."
                ),
            })
    return hits

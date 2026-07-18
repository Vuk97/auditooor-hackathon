"""
division_before_multiplication.py

Flags `a / b * c` patterns where the division happens before the
multiplication → precision loss on integer types.  Halborn §7.19, §7.41.

tree-sitter-rust parses `a / b * c` as binary_expression(
    binary_expression(a, /, b), *, c)
Detection: walk binary_expression nodes where operator is `*` AND the left
child is another binary_expression whose operator is `/` (or `%`).

We suppress obvious FP-friendly cases:
  - Pure literal folding (a/2*3 with all integer literals → usually
    intentional bit-tricks; we still flag because it's rarely safe in
    financial code).
  - Right operand is `1` or `2` exponent — noisy in math code; we keep it,
    acceptable FP level.
"""

from __future__ import annotations

from _util import walk, text_of, line_col, snippet_of


def run(tree, source: bytes, filepath: str):
    hits = []
    for n in walk(tree.root_node):
        if n.type != "binary_expression":
            continue
        # Find operator + operands
        op = None
        left = None
        right = None
        for c in n.children:
            if c.type in ("*", "/", "%", "+", "-", "<<", ">>", "&", "|", "^"):
                op = c.type
            elif left is None and c.type not in ("(", ")"):
                left = c
            else:
                right = c
        if op != "*":
            continue
        if left is None or left.type != "binary_expression":
            continue
        # left.op must be / or %
        left_op = None
        for c in left.children:
            if c.type in ("/", "%", "*", "+", "-"):
                left_op = c.type
                break
        if left_op not in ("/", "%"):
            continue
        text = text_of(n, source)
        # Skip trivial f64/f32 math (very rare in Soroban, but still)
        if ".0" in text or "f32" in text or "f64" in text:
            continue
        line, col = line_col(n)
        hits.append({
            "severity": "med",
            "line": line,
            "col": col,
            "snippet": snippet_of(n, source),
            "message": ("division-before-multiplication: "
                        "`a / b * c` precision loss (Halborn §7.19/§7.41)."),
        })
    return hits

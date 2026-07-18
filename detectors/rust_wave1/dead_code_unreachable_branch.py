"""
dead_code_unreachable_branch.py

Flags:
  - `if false { ... }` / `if true { ... } else { ... }` — the `else` arm
    is dead.
  - A statement appearing AFTER `panic!(...)`, `unreachable!(...)`,
    `return`, or `continue`/`break` in the same block (tree-sitter
    `block` node children).

We conservatively only fire on:
  1. `if_expression` condition is a `boolean_literal`.
  2. or: inside a `block` we find a control-flow terminator statement,
     and there is at least one non-attribute, non-comment sibling after it.
"""

from __future__ import annotations

import re

from _util import (
    function_items, walk, text_of, line_col, snippet_of, in_test_cfg,
)


_TERMINATOR_SUBSTR = ("panic!", "unreachable!", "return",
                      "continue", "break")


def _is_terminator_stmt(node, source: bytes) -> bool:
    if node.type == "expression_statement":
        for c in node.children:
            if c.type == "return_expression":
                return True
            if c.type == "macro_invocation":
                t = text_of(c, source)
                if t.startswith("panic!") or t.startswith("unreachable!"):
                    return True
    if node.type == "return_expression":
        return True
    return False


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        # Check if_expression with boolean literal conditions
        for n in walk(fn):
            if n.type == "if_expression":
                # condition = first child after `if` keyword
                cond = None
                for c in n.children:
                    if c.type == "boolean_literal":
                        cond = c
                        break
                if cond is not None:
                    line, col = line_col(n)
                    val = text_of(cond, source)
                    hits.append({
                        "severity": "low",
                        "line": line,
                        "col": col,
                        "snippet": snippet_of(n, source),
                        "message": (
                            f"`if {val} {{ ... }}` — constant-condition "
                            f"branch; dead code."
                        ),
                    })

            if n.type != "block":
                continue
            # Walk statement children, look for terminator followed by
            # anything non-trivial.
            stmts = [c for c in n.children
                     if c.type not in ("{", "}", "comment",
                                       "line_comment", "block_comment",
                                       "attribute_item")]
            for i, s in enumerate(stmts):
                if _is_terminator_stmt(s, source):
                    if i + 1 < len(stmts):
                        tail = stmts[i + 1]
                        line, col = line_col(tail)
                        hits.append({
                            "severity": "low",
                            "line": line,
                            "col": col,
                            "snippet": snippet_of(tail, source),
                            "message": (
                                f"statement after a `return` / `panic!` / "
                                f"`unreachable!` — dead code."
                            ),
                        })
                    break
    return hits

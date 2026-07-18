"""
r94_loop_state_mutation_before_check.py

Flags pub fns that mutate state (assign to a struct field / self.field) and
THEN run a validity check involving that same field. The check sees the
post-mutation state so passes trivially.

Source: Solodit #57695 (Code4rena Starknet Perpetual — _execute_transfer).
Class: state-mutation-before-check (both).

Heuristic:
  1. Body has a mutation `self.X = ...` or `positions[a].X = ...` or
     `position.field = ...`.
  2. AFTER that mutation, body has a `require(...)` / `assert!(...)` that
     references the same field name.
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)

_MUTATION_RE = re.compile(
    r"(?:self\.|\w+\.|\w+\[[^\]]+\]\.)(\w+)\s*(?:=|\+=|-=|\*=|/=)\s*[^;=]"
)
_CHECK_RE = re.compile(r"(require!?|assert!?|ensure)\s*\(")


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

        mutations = [(m.start(), m.group(1)) for m in _MUTATION_RE.finditer(body_nc)]
        if not mutations:
            continue

        checks = list(_CHECK_RE.finditer(body_nc))
        if not checks:
            continue

        # For each mutation-field, if ANY check AFTER it references the field
        for mstart, field in mutations:
            for c in checks:
                if c.start() <= mstart:
                    continue
                check_text = body_nc[c.start():c.start() + 200]
                if re.search(rf"\b{re.escape(field)}\b", check_text):
                    line, col = line_col(fn)
                    hits.append({
                        "severity": "high",
                        "line": line,
                        "col": col,
                        "snippet": snippet_of(fn, source)[:200],
                        "message": (
                            f"pub fn `{name}` mutates `{field}` then checks "
                            f"its value. The check sees post-mutation state. "
                            f"Move the check BEFORE the mutation or perform "
                            f"the check on the pending-diff. See Solodit "
                            f"#57695 (Starknet Perpetual)."
                        ),
                    })
                    break
            else:
                continue
            break
    return hits

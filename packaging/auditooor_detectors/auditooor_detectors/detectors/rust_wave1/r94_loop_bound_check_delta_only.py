"""
r94_loop_bound_check_delta_only.py

Flags extend/increment fns that check the DELTA arg against a MAX
constant without checking the RESULTING SUM.

Source: Solodit #55276 (Code4rena Initia).
Class: bound-check-delta-only (both).

Heuristic:
  1. Fn name matches /extend_|increase_|add_|increment_/.
  2. Body has `require!(delta_arg <= MAX_CONST)` / `if delta > MAX` etc.
  3. Body has a mutation `field += delta_arg` / `field = field + delta_arg`.
  4. Body does NOT have a post-sum check `require(new_field <= MAX_CONST)`.
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)

_FN_NAME_RE = re.compile(r"^(extend_\w+|increase_\w+|add_\w+|increment_\w+|prolong_\w+)$", re.IGNORECASE)


def run(tree, source: bytes, filepath: str):
    hits = []
    root = tree.root_node
    for fn, _impl in functions_in_contractimpl(root, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)

        # Find delta-param vs MAX_CONST pattern
        delta_check = re.search(
            r"require!?\s*\(\s*(\w+)\s*<=?\s*([A-Z_][A-Z0-9_]*MAX[A-Z0-9_]*|MAX_[A-Z0-9_]+)",
            body_nc,
        )
        if delta_check is None:
            delta_check = re.search(
                r"assert!?\s*\(\s*(\w+)\s*<=?\s*([A-Z_][A-Z0-9_]*MAX[A-Z0-9_]*|MAX_[A-Z0-9_]+)",
                body_nc,
            )
        if delta_check is None:
            continue
        delta_arg = delta_check.group(1)
        max_const = delta_check.group(2)

        # Does body mutate a field by delta_arg?
        if not re.search(rf"\+=\s*{re.escape(delta_arg)}|=\s*\w+\s*\+\s*{re.escape(delta_arg)}", body_nc):
            continue

        # Post-sum check against same MAX_CONST?
        # Look for pattern like `new_val <= MAX_CONST` or `field <= MAX_CONST` AFTER addition
        if re.search(rf"\w+\s*<=?\s*{re.escape(max_const)}\s*[,\)]", body_nc[delta_check.end():]):
            # If it's the same delta_arg again, no — if different var, OK
            trailing = body_nc[delta_check.end():]
            sum_check = re.search(rf"(\w+)\s*<=?\s*{re.escape(max_const)}", trailing)
            if sum_check and sum_check.group(1) != delta_arg:
                continue

        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` validates the DELTA (`{delta_arg}`) "
                f"against `{max_const}` but mutates a stored field with "
                f"`+= {delta_arg}` WITHOUT a post-sum check against the "
                f"same cap. Repeated calls bypass the cap. See Solodit "
                f"#55276 (Initia)."
            ),
        })
    return hits

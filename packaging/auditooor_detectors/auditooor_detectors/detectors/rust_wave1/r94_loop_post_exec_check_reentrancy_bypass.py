"""
r94_loop_post_exec_check_reentrancy_bypass.py

Flags fns with a `check_after_execution` / `post_exec_check` / `after_hook`
style that compares post-state to pre-state but the external execution
between them can mutate the same variable reentrantly.

Source: Solodit #6718 (Sherlock Hats).
Class: post-exec-check-reentrancy-bypass (both).

Heuristic:
  1. Fn reads a snapshot (e.g., let modules_before = get_modules())
  2. Fn calls an external execution (.call, execute, dispatch)
  3. Fn reads the snapshot again for comparison
  4. No nonReentrant guard
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name, text_of, line_col, snippet_of, is_pub, body_text_nocomment, IDENT,
)

_FN_NAME_RE = re.compile(r"(?i)(check_after_execution|post_exec|after_hook|verify_no_changes)")
_PRE_POST_SNAPSHOT_RE = re.compile(
    fr"let\s+{IDENT}before\s*=.*?let\s+{IDENT}after\s*=|"
    fr"let\s+{IDENT}_pre\s*=.*?let\s+{IDENT}_post\s*=|"
    r"snapshot\s*=.*?compare\s*\(",
    re.DOTALL,
)
_EXEC_BETWEEN_RE = re.compile(
    r"\.execute\s*\(|\.call\s*\(|dispatch\s*\(|invoke\s*\(|run_transaction"
)
_GUARD_RE = re.compile(r"nonReentrant|non_reentrant|reentrancy_guard")


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
        if _GUARD_RE.search(body_nc):
            continue
        if not _PRE_POST_SNAPSHOT_RE.search(body_nc):
            continue
        if not _EXEC_BETWEEN_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` takes before/after snapshots around an "
                f"external execution with no nonReentrant guard. "
                f"Reentrancy can alter state + restore it — post-check "
                f"passes. See Solodit #6718 (Hats)."
            ),
        })
    return hits

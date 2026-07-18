"""
r94_loop_sorted_list_wrong_end_traversal.py

Flags iteration over a sorted-by-ratio structure that starts at
`head` / `first` / `max` when the worst-case element is at `tail` /
`last` / `min` (or vice versa).

Source: Solodit #46889 (OtterSec Fluid Protocol Fuel).
Class: sorted-list-wrong-end-traversal (both).

Heuristic (coarse):
  1. Fn name matches /require_no|find_worst|liquidate_worst|check_all_troves|scan_troves/.
  2. Body iterates `head` / `first` / `get_first` via `.next` /
     `.following` — but the sort order implied by the fn's intent
     is opposite.
  3. A safer sibling (`tail` / `get_last` / `.prev`) is present in source
     but not called by this fn.
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
    source_nocomment,
)

_FN_NAME_RE = re.compile(r"(?i)(require_no_undercollat|find_worst|scan_troves|check_all|liquidate_worst)")
_WALK_HEAD_RE = re.compile(r"\.first\s*\(\)|get_first|head\s*\(\)|\.next\s*\(\)")
_TAIL_ALT_RE = re.compile(r"\.last\s*\(\)|get_last|tail\s*\(\)|\.prev\s*\(\)")


def run(tree, source: bytes, filepath: str):
    hits = []
    root = tree.root_node
    src_nc = source_nocomment(source)
    # Source must define both first/last accessors (otherwise no ambiguity)
    if not (_WALK_HEAD_RE.search(src_nc) and _TAIL_ALT_RE.search(src_nc)):
        return hits

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
        if not _WALK_HEAD_RE.search(body_nc):
            continue
        if _TAIL_ALT_RE.search(body_nc):
            continue  # uses both or only tail — OK
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` iterates from head/first of a sorted "
                f"structure while the module also exposes tail/last. "
                f"Likely walking the wrong end — worst-case elements "
                f"aren't inspected. See Solodit #46889 (Fluid Fuel)."
            ),
        })
    return hits

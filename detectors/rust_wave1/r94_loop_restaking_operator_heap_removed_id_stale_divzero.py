"""
r94_loop_restaking_operator_heap_removed_id_stale_divzero.py

Flags deposit / withdrawal allocation fns that iterate an operator
heap / priority queue and divide / compute allocation per entry
without skipping entries whose `operator_id == 0` (sentinel for
removed). Iteration hits a stale zombie and divides by zero / reads
stale utilization.

Source: Solodit #30903 (Sherlock Rio Network).
Class: restaking-operator-heap-removed-id-stale-divzero (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(
    r"(?i)(allocate_deposits|allocate_withdrawals|"
    r"distribute_deposits|distribute_withdrawals|"
    r"select_operator|pick_operator|next_operator|"
    r"rebalance_heap|walk_heap)"
)
# Must iterate heap / priority queue.
_HEAP_ITER_RE = re.compile(
    r"(?i)(heap\s*\.\s*iter|heap\s*\[\s*\w+\s*\]|"
    r"priority_queue\s*\.\s*iter|priority_queue\s*\[|"
    r"operator_heap|operator_queue|"
    r"utilization_heap|active_operators|"
    fr"for\s+\w+\s+in\s+{IDENT}heap)"
)
# Safe: skip removed / zero id entries before arithmetic.
_SKIP_ZERO_RE = re.compile(
    r"(?i)(if\s+[\w\.]*operator_id\s*==\s*0|"
    r"if\s+[\w\.]*op_id\s*==\s*0|"
    r"if\s+[\w\.]*id\s*==\s*0\s*\{|"
    r"continue\s*;\s*\/\/\s*removed|"
    r"is_removed|is_active\s*\(|has_been_removed|"
    r"is_tombstone|heap\.is_live|entry\.active)"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        if not _HEAP_ITER_RE.search(body_nc):
            continue
        if _SKIP_ZERO_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` iterates the operator heap / "
                f"priority-queue without skipping tombstone entries "
                f"(operator_id == 0, is_removed) — deposit / withdrawal "
                f"allocation divides by zero on a removed zombie slot "
                f"(restaking-operator-heap-removed-id-stale-divzero). "
                f"See Solodit #30903 (Sherlock Rio Network)."
            ),
        })
    return hits

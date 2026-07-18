"""
r94_loop_global_vs_per_group_trigger.py

Flags ADL / liquidation / insurance-fund trigger fns that compare
a GLOBAL aggregate (total_debt, global_utilization) when a PER-GROUP
local value was the intended trigger.

Source: Solodit #65264 (Sherlock CurrentSUI).
Class: global-vs-per-group-trigger (both).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name, text_of, line_col, snippet_of, is_pub, body_text_nocomment, IDENT,
)

_FN_NAME_RE = re.compile(fr"(?i)(adl|auto_deleverage|trigger|should_{IDENT}deleverage|check_deleverage|compute_liq_target)")

_GLOBAL_AGG_RE = re.compile(
    r"total_(debt|utilization|collateral|supply)\s*[<>]=|"
    r"global_(debt|utilization)\s*[<>]=|"
    r"market_total_(debt|borrow)\s*[<>]=|"
    fr"protocol_{IDENT}_(debt|utilization)\s*[<>]="
)

_PER_GROUP_CONTEXT_RE = re.compile(
    r"group|coin_type|mint|asset|bucket|tier|reserve_id"
)


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
        if not _GLOBAL_AGG_RE.search(body_nc):
            continue
        # Must be in a context where groups exist (if no per-group context, skip)
        if not _PER_GROUP_CONTEXT_RE.search(body_nc):
            continue
        # Heuristic: if body has BOTH group-indexed aggregates AND global aggregates,
        # it's probably OK (multi-level checks). Only flag when no group-indexed
        # aggregate is present alongside the global one.
        if re.search(fr"groups?\[[^\]]+\]\.{IDENT}_?(debt|utilization|collateral)\s*[<>]=|"
                     r"per_group_\w*\s*[<>]=", body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "medium",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` is an ADL / deleverage trigger in a "
                f"per-group context but compares a GLOBAL aggregate "
                f"(total_debt / global_utilization). Healthy groups get "
                f"force-liquidated for another group's debt. See Solodit "
                f"#65264 (CurrentSUI)."
            ),
        })
    return hits

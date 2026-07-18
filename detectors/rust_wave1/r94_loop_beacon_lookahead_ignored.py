"""
r94_loop_beacon_lookahead_ignored.py

Flags Ethereum consensus-layer fns that compute the beacon proposer
index using `effective_balance` / `get_beacon_proposer_indices` /
`compute_shuffled_index` WITHOUT consulting the proposer-lookahead
cache. Balance updates between slot and lookahead drift the
proposer assignment.

Source: Solodit #64102 (Sherlock Fusaka Upgrade).
Class: beacon-lookahead-ignored (rust_only).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)

_FN_NAME_RE = re.compile(
    r"(?i)(get_beacon_proposer|compute_proposer|select_proposer|"
    r"proposer_index|beacon_proposer|get_next_proposer)"
)
_EFFECTIVE_BAL_RE = re.compile(
    r"effective_balance|get_effective_balance|compute_shuffled_index|"
    r"compute_committee|\.validator\.effective"
)
_LOOKAHEAD_RE = re.compile(
    r"proposer_lookahead|lookahead_proposer|lookahead_cache|"
    r"lookahead_epoch|next_proposer_lookahead|proposer_preimage_cache"
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
        if not _EFFECTIVE_BAL_RE.search(body_nc):
            continue
        if _LOOKAHEAD_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` computes proposer index from "
                f"effective_balance without consulting the proposer-"
                f"lookahead cache. Balance updates between slot and "
                f"lookahead drift proposer assignment. See Solodit #64102 "
                f"(Fusaka Upgrade)."
            ),
        })
    return hits

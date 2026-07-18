"""
r94_loop_checkpoint_same_block_ambiguity.py

Flags fns using `checkpoint.get_at_block(...)` / `getAtBlock(...)` that
select a checkpoint at a specific block without disambiguating
multiple same-block checkpoints (e.g., using timestamp or seqNo).

Source: Solodit #3632 (Telcoin).
Class: checkpoint-same-block-ambiguity (rust side).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_CHECKPOINT_CALL_RE = re.compile(r"getAtBlock\s*\(|get_at_block\s*\(|getPastVotesAt\s*\(")
_DISAMBIG_RE = re.compile(
    r"timestamp|seqNo|sequence_number|ordinal|within_block_order|"
    r"getAtTimestamp|same_block_index"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        if not _CHECKPOINT_CALL_RE.search(body_nc):
            continue
        if _DISAMBIG_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "medium",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` calls checkpoint.getAtBlock without "
                f"disambiguating multiple same-block checkpoints. "
                f"Flash stake+exit in same block fakes stake value. "
                f"See Solodit #3632 (Telcoin)."
            ),
        })
    return hits

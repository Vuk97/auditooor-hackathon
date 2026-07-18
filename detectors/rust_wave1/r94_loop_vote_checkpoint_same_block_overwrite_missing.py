"""
r94_loop_vote_checkpoint_same_block_overwrite_missing.py

Flags `_write_checkpoint` / `push_checkpoint` fns that unconditionally
append a new entry without checking whether the most-recent entry
has the same timestamp/block — two interactions in the same block
create duplicate checkpoints, making binary-search past-votes
lookups return the earlier value.

Source: Solodit #3265 (Code4rena Nouns Builder ERC721Votes).
Class: vote-checkpoint-same-block-overwrite-missing (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(_write_checkpoint|write_checkpoint|"
    r"push_checkpoint|append_checkpoint|"
    r"record_checkpoint|add_checkpoint)"
)
# Unconditional push / append.
_APPEND_RE = re.compile(
    fr"(?i)(checkpoints\s*\.\s*push\s*\(|"
    fr"\.\s*push\s*\(\s*Checkpoint|"
    fr"checkpoints\s*\.\s*append\s*\(|"
    fr"checkpoints\[\s*{IDENT}length\s*\]\s*=\s*Checkpoint|"
    fr"ckpts\s*\.\s*push\s*\()"
)
# Safe: checks last.block/timestamp == current before overwriting.
_LAST_MATCH_RE = re.compile(
    fr"(?i)(last\.block_number\s*==\s*{IDENT}block\s*\.\s*number|"
    fr"last\.fromBlock\s*==\s*block\.number|"
    fr"last\.timestamp\s*==\s*block\.timestamp|"
    fr"last_checkpoint\.timestamp\s*==\s*{IDENT}block|"
    fr"ckpt\.block_number\s*==\s*block\s*\.\s*number|"
    fr"checkpoints\s*\[[^\]]+\]\s*\.\s*from_block\s*==\s*{IDENT}(block|current)|"
    fr"checkpoints\s*\[[^\]]+\]\s*\.\s*fromBlock\s*==|"
    fr"checkpoints\s*\[[^\]]+\]\s*\.\s*timestamp\s*==|"
    fr"ckpts\s*\[[^\]]+\]\s*\.\s*(from|block|timestamp)\s*==|"
    fr"if\s+{IDENT}pos\s*>\s*0\s*&&\s*{IDENT}last\.\w*(from|block|timestamp)|"
    fr"if\s+{IDENT}pos\s*!=\s*0\s*&&\s*{IDENT}last\.\w*(from|block|timestamp)|"
    fr"overwrite_last_checkpoint|update_last_checkpoint)"
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
        if not _APPEND_RE.search(body_nc):
            continue
        if _LAST_MATCH_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` appends a new checkpoint without "
                f"checking whether the last entry shares the current "
                f"block / timestamp — duplicate same-block checkpoints "
                f"break binary-search past-voting-power lookups "
                f"(vote-checkpoint-same-block-overwrite-missing). "
                f"See Solodit #3265 (Code4rena Nouns Builder)."
            ),
        })
    return hits

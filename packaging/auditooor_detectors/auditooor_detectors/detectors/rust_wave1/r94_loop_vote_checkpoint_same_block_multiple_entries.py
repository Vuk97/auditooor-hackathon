"""
r94_loop_vote_checkpoint_same_block_multiple_entries.py

Flags _writeCheckpoint-style fns that push a new entry unconditionally
instead of mutating the last entry when its timestamp equals the
current timestamp — flash transfers in the same block produce stale
binary-search results.

Source: Solodit #3265 (Nouns Builder ERC721Votes).
Class: vote-checkpoint-same-block-multiple-entries (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(r"(?i)(write_checkpoint|_write_checkpoint|record_votes|update_voting_power|write_vote)")
_PUSH_RE = re.compile(
    fr"\.push\s*\(\s*{IDENT}Checkpoint|checkpoints?\s*\(\s*\w*\s*\)\s*\.push|"
    r"checkpoints?\s*\.\s*push|"
    r"vote_history\.push|history\.push\s*\(|new_vec\.push"
)
_SAMESTAMP_MERGE_RE = re.compile(
    r"(last\.timestamp|back\(\)\.timestamp|prev\.timestamp)\s*==\s*(now|block_timestamp|ledger_timestamp|env\.ledger\.timestamp)|"
    r"if\s+\w+\.last\(\)\s*\.timestamp\s*==\s*\w+|"
    r"last_checkpoint_ts\s*==\s*now|"
    r"\.last_mut\(\)"
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
        if not _PUSH_RE.search(body_nc):
            continue
        if _SAMESTAMP_MERGE_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` pushes a new checkpoint per call "
                f"without merging when the last entry shares the "
                f"current timestamp — binary search returns stale "
                f"vote power for same-block flash transfers "
                f"(vote-checkpoint-same-block-multiple-entries). "
                f"See Solodit #3265 (Nouns Builder)."
            ),
        })
    return hits

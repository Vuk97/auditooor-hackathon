"""
zebra_header_context_validation_gap.py

Flags acceptance-oriented Rust functions that rely on local header checks
like proof-of-work threshold, Equihash, Merkle-root, or chain-history
commitment validation, but never bind the candidate to recent chain context
such as parent linkage, median-time-past, or expected difficulty.

This detector is intentionally conservative and Zebra-fit. It looks for:

1. A local header validation call,
2. A verified-block or checkpoint-commit sink, and
3. No recent-chain context binders in the same function,

while rejecting functions that explicitly reference recent-chain binders like
`AdjustedDifficulty::new_from_header_time`, `expected_difficulty_threshold`,
`median_time_past`, `previous_block_hash`, or `block_is_valid_for_recent_chain`.
"""

from __future__ import annotations

import re

from _util import (
    body_text_nocomment,
    fn_body,
    fn_name,
    function_items,
    in_test_cfg,
    line_col,
    snippet_of,
)


_LOCAL_HEADER_CHECK_RE = re.compile(
    r"\b("
    r"difficulty_threshold_is_valid|"
    r"difficulty_is_valid|"
    r"equihash_solution_is_valid|"
    r"merkle_root_validity|"
    r"block_commitment_is_valid_for_chain_history"
    r")\b"
)

_ACCEPT_SINK_RE = re.compile(
    r"\b("
    r"[A-Za-z0-9_]*VerifiedBlock::new|"
    r"CommitCheckpointVerifiedBlock"
    r")\b"
)

_CONTEXT_BINDER_RE = re.compile(
    r"\b("
    r"block_is_valid_for_recent_chain|"
    r"AdjustedDifficulty::new_from_header_time|"
    r"expected_difficulty_threshold|"
    r"median_time_past|"
    r"previous_block_hash|"
    r"parent_height|"
    r"height_one_more_than_parent_height|"
    r"relevant_chain|"
    r"best_relevant_chain|"
    r"any_ancestor_blocks|"
    r"block_is_not_orphaned"
    r")\b"
)


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        body_nc = body_text_nocomment(body, source)

        local_checks = sorted(set(_LOCAL_HEADER_CHECK_RE.findall(body_nc)))
        if not local_checks:
            continue
        if not _ACCEPT_SINK_RE.search(body_nc):
            continue
        if _CONTEXT_BINDER_RE.search(body_nc):
            continue

        name = fn_name(fn, source)
        line, col = line_col(fn)
        hits.append({
            "severity": "medium",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:220],
            "message": (
                f"fn `{name}` accepts or produces a verified block using local "
                f"header checks {local_checks}, but does not reference recent "
                "chain binders like parent linkage, median-time-past, or "
                "expected difficulty (zebra-header-context-validation-gap)."
            ),
        })

    return hits

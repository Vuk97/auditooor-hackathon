"""
header_context_validation_bypass_fire21.py

Fire21 Rust lift for header-context-validation-bypass.

Flags acceptance-oriented Rust functions that validate header hash, work,
parent, or timestamp fields locally and then accept or store the header without
binding it to network, height, branch, checkpoint, or trusted-root context.

Detector hits are candidate evidence only.
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


DETECTOR_ID = "rust_wave1.header_context_validation_bypass_fire21"

_HEADER_SURFACE_RE = re.compile(
    r"(?i)\b(?:header|block_header|candidate_header|checkpoint_header|"
    r"HeaderFor|BlockHeader|Header)\b"
)

_LOCAL_HEADER_CHECK_RE = re.compile(
    r"(?i)\b(?:"
    r"(?:validate|verify|check|ensure|assert)[a-z0-9_]*"
    r"(?:header|hash|work|pow|proof_of_work|difficulty|parent|previous|"
    r"timestamp|time)[a-z0-9_]*|"
    r"difficulty_threshold_is_valid|difficulty_is_valid|"
    r"equihash_solution_is_valid|merkle_root_validity|"
    r"block_commitment_is_valid_for_chain_history|hash_is_valid|"
    r"work_is_valid|parent_hash_is_valid|timestamp_is_valid"
    r")\s*\("
)

_HEADER_FIELD_RE = re.compile(
    r"(?i)\b(?:"
    r"(?:header|block\.header|candidate(?:_header)?)[a-z0-9_\.()]*"
    r"(?:hash|parent|previous_block_hash|timestamp|time|difficulty|bits|"
    r"n_bits|pow|work)|"
    r"(?:hash|work|difficulty|parent_hash|previous_block_hash|timestamp|"
    r"time|difficulty_threshold|n_bits|proof_of_work|header_hash)"
    r")\b"
)

_ACCEPT_SINK_RE = re.compile(
    r"(?is)"
    r"(?:\b(?:Verified|Accepted|Trusted|CheckpointVerified|Stored)"
    r"(?:Block|Header)::new\s*\(|"
    r"\b(?:accept|commit|store|insert|push|connect|queue|finalize)"
    r"[a-z0-9_]*(?:header|block)[a-z0-9_]*\s*\(|"
    r"\.\s*(?:insert|push)\s*\([^;{}]{0,220}\b(?:header|block)\b)"
)

_CONTEXT_BINDER_RE = re.compile(
    r"(?is)\b(?:"
    r"(?:bind|require|ensure|validate|verify|check|assert)[a-z0-9_]*"
    r"(?:network|height|branch|checkpoint|trusted_?root|trusted_?anchor|"
    r"trusted_?checkpoint|chain_?context|parent_?height|best_?chain|"
    r"relevant_?chain|canonical_?chain|main_?chain|median_?time_?past)|"
    r"AdjustedDifficulty::new_from_header_time|"
    r"expected_difficulty_threshold|median_time_past|"
    r"block_is_valid_for_recent_chain|block_is_not_orphaned|"
    r"height_one_more_than_parent_height|parent_height|"
    r"trusted_root|trusted_anchor|trusted_checkpoint|checkpoint|"
    r"relevant_chain|best_relevant_chain|known_branch|canonical_chain|"
    r"branch_contains|contains_header_hash|is_descendant_of|"
    r"is_on_main_chain|is_known_at_height|height_for_hash"
    r")\b"
)


def _local_check_terms(body: str) -> list[str]:
    return sorted(
        {
            match.group(0).strip().removesuffix("(")
            for match in _LOCAL_HEADER_CHECK_RE.finditer(body)
        }
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
        name = fn_name(fn, source)
        surface = f"{name}\n{body_nc}"

        if not _HEADER_SURFACE_RE.search(surface):
            continue

        local_checks = _local_check_terms(body_nc)
        if not local_checks:
            continue
        if not _HEADER_FIELD_RE.search(body_nc):
            continue
        if not _ACCEPT_SINK_RE.search(body_nc):
            continue
        if _CONTEXT_BINDER_RE.search(body_nc):
            continue

        line, col = line_col(fn)
        hits.append(
            {
                "detector_id": DETECTOR_ID,
                "severity": "high",
                "file": filepath,
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:220],
                "message": (
                    f"header context validation bypass in `{name}`: local "
                    f"header checks {local_checks} lead to an accepted or "
                    "stored header without network, height, branch, "
                    "checkpoint, or trusted-root binding."
                ),
            }
        )

    return hits

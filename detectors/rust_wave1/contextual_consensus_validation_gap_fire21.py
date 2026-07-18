"""
contextual_consensus_validation_gap_fire21.py

Fire21 same-class Rust lift for contextual-consensus-validation-gap.

Confirmed source:
- zebra-anchor-contextual-validation-gap-positive

Detector hits are candidate evidence only. They flag consensus validation code
that accepts anchor or tree-state material without binding it to the contextual
chain state it is meant to validate.
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


DETECTOR_ID = "rust_wave1.contextual_consensus_validation_gap_fire21"

_CONSENSUS_CONTEXT_RE = re.compile(
    r"(?i)\b("
    r"consensus|finali[sz]ed|non_?finali[sz]ed|parent_?chain|"
    r"chain_?context|treestate|tree_?state|sapling|sprout|anchor|"
    r"state_?root|root|height|network|chain_?id"
    r")\b"
)

_ANCHOR_ITER_RE = re.compile(
    r"(?is)\bfor\s+\w*anchor\w*\s+in\s+"
    r"[^{}]{0,220}\b(?:sapling_anchors|anchors)\s*\("
)
_FINALIZED_ANCHOR_ACCEPT_RE = re.compile(
    r"(?is)\b(?:finalized_state|final_state)\s*\.\s*"
    r"(?:contains_sapling_anchor|contains_anchor|has_anchor|anchor_exists)\s*\("
)
_CONTEXT_AVAILABLE_RE = re.compile(
    r"(?is)\b(parent_chain|non_?finali[sz]ed|struct\s+Chain|chain_context)\b"
    r"[\s\S]{0,1600}\b(?:sapling_anchors|anchors|treestate|tree_by_anchor)"
)
_ANCHOR_CONTEXT_BIND_RE = re.compile(
    r"(?is)\b(?:parent_chain|non_?finali[sz]ed|chain|chain_context|context)\b"
    r"[^{};]{0,360}\b"
    r"(?:sapling_anchors|anchors|contains_sapling_anchor|contains_anchor|"
    r"has_anchor|anchor_exists)\b"
)

_CONTEXTUAL_TREE_LOOKUP_RE = re.compile(
    r"(?is)\b(?:parent_chain|non_?finali[sz]ed|chain_context)\b"
    r"[^{}]{0,900}\b(?:sprout_trees_by_anchor|tree_by_anchor|"
    r"treestate|tree_state|trees_by_anchor)\b"
    r"[^{}]{0,900}\b(?:finalized_state|final_state)\b"
)
_TREESTATE_ACCEPT_RE = re.compile(
    r"(?is)\b(?:sprout_final_treestates|final_treestates|treestates|"
    r"accepted_trees|trees_by_anchor)\s*\.\s*(?:insert|push)\s*\("
    r"[^;{}]{0,260}\b(?:anchor|root)\b[^;{}]{0,260}\b"
    r"(?:input_tree|tree)\b"
)
_ROOT_TO_ANCHOR_BIND_RE = re.compile(
    r"(?is)("
    r"(?:assert_eq!|ensure!|assert!|debug_assert_eq!)\s*\("
    r"[^;{}]{0,220}\b(?:input_tree|tree)\s*\.\s*root\s*\(\s*\)"
    r"[^;{}]{0,220}\b(?:joinsplit\.)?anchor\b|"
    r"\b(?:input_tree|tree)\s*\.\s*root\s*\(\s*\)"
    r"[^;{}]{0,180}(?:==|!=)[^;{}]{0,180}\b(?:joinsplit\.)?anchor\b"
    r")"
)


def _signature_text(fn, body, source: bytes) -> str:
    return source[fn.start_byte:body.start_byte].decode("utf-8", errors="replace")


def _finalized_only_anchor_acceptance(signature: str, body: str, file_text: str) -> str | None:
    joined = f"{signature}\n{body}"
    if not _ANCHOR_ITER_RE.search(body):
        return None
    if not _FINALIZED_ANCHOR_ACCEPT_RE.search(body):
        return None
    if not _CONTEXT_AVAILABLE_RE.search(f"{joined}\n{file_text[:4000]}"):
        return None
    if _ANCHOR_CONTEXT_BIND_RE.search(body):
        return None
    return "accepts transaction anchors from finalized state without binding available parent-chain context"


def _treestate_without_root_binding(signature: str, body: str) -> str | None:
    joined = f"{signature}\n{body}"
    if not _CONTEXTUAL_TREE_LOOKUP_RE.search(joined):
        return None
    if not _TREESTATE_ACCEPT_RE.search(body):
        return None
    if _ROOT_TO_ANCHOR_BIND_RE.search(body):
        return None
    return "accepts contextual treestate material without binding the tree root to the requested anchor"


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    file_text = source.decode("utf-8", errors="replace")

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue

        body_node = fn_body(fn)
        if body_node is None:
            continue

        name = fn_name(fn, source)
        signature = _signature_text(fn, body_node, source)
        body = body_text_nocomment(body_node, source)
        context = f"{name}\n{signature}\n{body}\n{file_text[:3000]}"
        if not _CONSENSUS_CONTEXT_RE.search(context):
            continue

        reason = (
            _finalized_only_anchor_acceptance(signature, body, file_text)
            or _treestate_without_root_binding(signature, body)
        )
        if reason is None:
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
                    f"contextual-consensus-validation-gap in `{name}`: {reason}. "
                    "Bind anchor, root, height, network, or state context before "
                    "accepting the consensus value."
                ),
            }
        )

    return hits

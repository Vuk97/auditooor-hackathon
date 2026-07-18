"""
consensus_state_root_or_context_gap_fire20.py

Fire20 Rust lift for consensus state-root and contextual-validation gaps.

Seed misses:
- rust-consensus-state-root-commitment-divergence-positive
- zebra-anchor-contextual-validation-gap-positive
- zebra-finalized-nonfinalized-fallback-gap-positive

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
    text_of,
)


DETECTOR_ID = "rust_wave1.consensus_state_root_or_context_gap_fire20"

_CONSENSUS_CONTEXT_RE = re.compile(
    r"(?i)\b("
    r"app_?hash|state_?root|commit_?root|commitment|merkle|"
    r"consensus|finali[sz]e|finali[sz]ed|non_?finali[sz]ed|"
    r"parent_?chain|header|block|anchor|sapling|sprout|"
    r"utxo|outpoint|treestate|chain_?order"
    r")\b"
)

_COMPUTED_ROOT_RE = re.compile(
    r"(?is)\b(?:let\s+)?(?P<computed>"
    r"computed_state_root|computed_root|expected_state_root|"
    r"local_state_root|recomputed_state_root|app_hash|computed_app_hash"
    r")\b\s*=\s*[^;]{0,220}\b(?:compute|calculate|derive|build|"
    r"execute|apply)[A-Za-z0-9_]*_?(?:state_?root|app_?hash|root)"
    r"\s*\("
)
_UNTRUSTED_ROOT_COMMIT_RE = re.compile(
    r"(?is)\b(?:commit_root|commit_state_root|commit_app_hash|"
    r"set_app_hash|write_state_root|store_state_root)\s*\("
    r"[^;{}]{0,220}\b(?:header|block|claimed|provided|remote|received)"
    r"[A-Za-z0-9_\.\(\)]{0,160}(?:state_?root|app_?hash|root)\b"
)
_ROOT_COMPARE_RE = re.compile(
    r"(?is)("
    r"(?:computed_state_root|computed_root|expected_state_root|"
    r"local_state_root|recomputed_state_root|computed_app_hash)"
    r"[^;{}]{0,180}(?:==|!=)"
    r"[^;{}]{0,180}(?:header|block|claimed|provided|remote|received)"
    r"[^;{}]{0,120}(?:state_?root|app_?hash|root)|"
    r"(?:assert_eq!|ensure!|assert!|debug_assert_eq!)\s*\("
    r"[^;{}]{0,220}(?:computed_state_root|computed_root|"
    r"expected_state_root|local_state_root|recomputed_state_root|"
    r"computed_app_hash)[^;{}]{0,220}(?:header|block|claimed|provided|"
    r"remote|received)[^;{}]{0,140}(?:state_?root|app_?hash|root)"
    r")"
)
_COMMIT_COMPUTED_RE = re.compile(
    r"(?is)\b(?:commit_root|commit_state_root|commit_app_hash|"
    r"set_app_hash|write_state_root|store_state_root)\s*\("
    r"\s*(?:computed_state_root|computed_root|expected_state_root|"
    r"local_state_root|recomputed_state_root|computed_app_hash)\b"
)

_SAPLING_ANCHOR_LOOP_RE = re.compile(
    r"(?is)\bfor\s+\w*anchor\w*\s+in\s+"
    r"[^{}]{0,180}\bsapling_anchors\s*\("
)
_FINALIZED_ANCHOR_CHECK_RE = re.compile(
    r"(?is)\bfinalized_state\s*\.\s*contains_sapling_anchor\s*\("
)
_PARENT_ANCHOR_CHECK_RE = re.compile(
    r"(?is)\b(?:parent_chain|non_?finali[sz]ed|chain)\b"
    r"[^{};]{0,240}\b(?:sapling_anchors|contains_sapling_anchor)"
    r"[^{};]{0,160}\bcontains\s*\("
)

_TREESTATE_INSERT_RE = re.compile(
    r"(?is)\b(?:sprout_final_treestates|final_treestates|treestates)"
    r"\s*\.\s*insert\s*\(\s*(?:joinsplit\.)?anchor\s*,\s*input_tree\s*\)"
)
_TREESTATE_CROSS_CONTEXT_RE = re.compile(
    r"(?is)(?:parent_chain|non_?finali[sz]ed)[^{}]{0,900}"
    r"(?:sprout_trees_by_anchor|tree_by_anchor|treestate)"
    r"[^{}]{0,900}(?:finalized_state|final_state)"
)
_TREE_ROOT_BINDING_RE = re.compile(
    r"(?is)("
    r"(?:assert_eq!|ensure!|assert!|debug_assert_eq!)\s*\("
    r"[^;{}]{0,180}\binput_tree\s*\.\s*root\s*\(\s*\)"
    r"[^;{}]{0,180}\b(?:joinsplit\.)?anchor\b|"
    r"\binput_tree\s*\.\s*root\s*\(\s*\)"
    r"[^;{}]{0,160}(?:==|!=)[^;{}]{0,160}\b(?:joinsplit\.)?anchor\b"
    r")"
)

_NONFINALIZED_UTXO_FALLBACK_RE = re.compile(
    r"(?is)\bnon_?finali[sz]ed(?:_chain)?_unspent_utxos"
    r"\s*\.\s*get\s*\(\s*&?\s*(?P<spend>\w+)\s*\)"
    r"[^{};]{0,220}\.or_else\s*\(\s*\|\|\s*"
    r"(?:finalized_state|final_state)\s*\.\s*utxo\s*\(\s*&?\s*(?P=spend)\s*\)"
)
_NONFINALIZED_SPENT_GUARD_RE = re.compile(
    r"(?is)\bnon_?finali[sz]ed(?:_chain)?_spent_utxos"
    r"\s*\.\s*contains_key\s*\(\s*&?\s*\w+\s*\)"
)


def _signature_text(fn, body, source: bytes) -> str:
    return source[fn.start_byte:body.start_byte].decode("utf-8", errors="replace")


def _root_commitment_gap(signature: str, body: str) -> str | None:
    joined = f"{signature}\n{body}"
    if not _COMPUTED_ROOT_RE.search(joined):
        return None
    if not _UNTRUSTED_ROOT_COMMIT_RE.search(body):
        return None
    if _ROOT_COMPARE_RE.search(body):
        return None
    if _COMMIT_COMPUTED_RE.search(body):
        return None
    return "commits a header or caller-provided state root without comparing it to the locally computed root"


def _finalized_only_anchor_gap(signature: str, body: str, file_text: str) -> str | None:
    joined = f"{signature}\n{body}"
    available_context = f"{joined}\n{file_text[:3000]}"
    if "parent_chain" not in available_context and "non_finalized" not in available_context:
        return None
    if not _SAPLING_ANCHOR_LOOP_RE.search(body):
        return None
    if not _FINALIZED_ANCHOR_CHECK_RE.search(body):
        return None
    if _PARENT_ANCHOR_CHECK_RE.search(body):
        return None
    return "validates transaction anchors against finalized state only while parent-chain context is available"


def _treestate_root_binding_gap(signature: str, body: str) -> str | None:
    joined = f"{signature}\n{body}"
    if not _TREESTATE_CROSS_CONTEXT_RE.search(joined):
        return None
    if not _TREESTATE_INSERT_RE.search(body):
        return None
    if _TREE_ROOT_BINDING_RE.search(body):
        return None
    return "moves a treestate between finalized and parent-chain contexts without binding the tree root to the requested anchor"


def _nonfinalized_fallback_gap(body: str) -> str | None:
    if not _NONFINALIZED_UTXO_FALLBACK_RE.search(body):
        return None
    if _NONFINALIZED_SPENT_GUARD_RE.search(body):
        return None
    return "falls back from non-finalized unspent UTXOs to finalized state without excluding non-finalized spends"


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
        fn_text = f"{name}\n{signature}\n{body}"
        if not _CONSENSUS_CONTEXT_RE.search(fn_text + "\n" + file_text[:3000]):
            continue

        reason = (
            _root_commitment_gap(signature, body)
            or _finalized_only_anchor_gap(signature, body, file_text)
            or _treestate_root_binding_gap(signature, body)
            or _nonfinalized_fallback_gap(body)
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
                    f"consensus context gap in `{name}`: {reason}. "
                    "Bind finalized or parent-chain context before committing "
                    "or accepting the consensus value."
                ),
            }
        )

    return hits

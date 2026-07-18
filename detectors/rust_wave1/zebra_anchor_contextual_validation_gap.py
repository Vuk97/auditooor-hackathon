"""
zebra_anchor_contextual_validation_gap.py

Flags Zebra-style shielded anchor validation code where consensus anchor
lookups are not bound to the contextual state that makes them valid.

This detector is intentionally Zcash/Zebra-shaped. It requires Sprout,
Sapling, Orchard, JoinSplit, ZebraDb, Chain, or note commitment tree terms;
it is not a Solana Anchor detector.

Candidate classes:
  1. Sapling or Orchard anchor checks that look only at one state surface,
     instead of requiring the parent non-finalized chain context plus the
     finalized DB anchor index.
  2. Sprout final treestate maps populated from an anchor lookup without an
     explicit tree.root() == anchor binding check before insertion.
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


DETECTOR_ID = "rust_wave1.zebra_anchor_contextual_validation_gap"

_ZEBRA_SHIELDED_RE = re.compile(
    r"\b(?:sprout|sapling|orchard|joinsplit|treestate|"
    r"note_commitment|NoteCommitmentTree|ZebraDb|ValidateContextError)\b",
    re.IGNORECASE,
)

_SAPLING_ORCHARD_ANCHOR_RE = re.compile(
    r"(?:contains_sapling_anchor\s*\(|contains_orchard_anchor\s*\(|"
    r"(?:sapling|orchard)_anchors\s*\.\s*contains\s*\(|"
    r"UnknownSaplingAnchor|UnknownOrchardAnchor)",
    re.IGNORECASE,
)

_PARENT_CHAIN_ANCHOR_RE = re.compile(
    r"(?:parent_chain|Arc\s*<\s*Chain\s*>|&\s*Chain|"
    r"chain\s*\.\s*(?:sapling|orchard)_anchors|"
    r"(?:sapling|orchard)_anchors\s*\.\s*contains\s*\()",
    re.IGNORECASE,
)

_FINALIZED_ANCHOR_RE = re.compile(
    r"(?:finalized_state\s*\.\s*contains_(?:sapling|orchard)_anchor\s*\(|"
    r"ZebraDb)",
    re.IGNORECASE,
)

_UNKNOWN_FINAL_ANCHOR_ERR_RE = re.compile(
    r"(?:ValidateContextError\s*::\s*Unknown(?:Sapling|Orchard)Anchor|"
    r"Unknown(?:Sapling|Orchard)Anchor)",
    re.IGNORECASE,
)

_SPROUT_TREE_LOOKUP_RE = re.compile(
    r"(?:sprout_trees_by_anchor\s*\.\s*get\s*\(|"
    r"sprout_tree_by_anchor\s*\(|"
    r"sprout_final_treestates\s*\.\s*insert\s*\()",
    re.IGNORECASE,
)

_SPROUT_INSERT_RE = re.compile(
    r"sprout_final_treestates\s*\.\s*insert\s*\([^;]*anchor[^;]*,\s*[^;]*(?:tree|input_tree)",
    re.IGNORECASE | re.DOTALL,
)


def _compact(text: str) -> str:
    return re.sub(r"\s+", "", text)


def _has_root_anchor_binding_guard(body_text: str) -> bool:
    compact = _compact(body_text)

    root_then_anchor = re.search(
        r"[A-Za-z0-9_\.]+\.root\(\)(?:==|!=)[A-Za-z0-9_\.]*anchor",
        compact,
        re.IGNORECASE,
    )
    anchor_then_root = re.search(
        r"[A-Za-z0-9_\.]*anchor(?:==|!=)[A-Za-z0-9_\.]+\.root\(\)",
        compact,
        re.IGNORECASE,
    )
    assert_eq_guard = re.search(
        r"(?:assert_eq!|debug_assert_eq!|ensure!)\([^)]*(?:root\(\)[^)]*anchor|anchor[^)]*root\(\))",
        compact,
        re.IGNORECASE,
    )

    return bool(root_then_anchor or anchor_then_root or assert_eq_guard)


def _is_zebra_shielded_function(fn_text: str, body_text: str) -> bool:
    return bool(_ZEBRA_SHIELDED_RE.search(fn_text) or _ZEBRA_SHIELDED_RE.search(body_text))


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        name = fn_name(fn, source)
        fn_text = text_of(fn, source)
        body_nc = body_text_nocomment(body, source)
        if not _is_zebra_shielded_function(fn_text, body_nc):
            continue

        line, col = line_col(fn)

        if _SAPLING_ORCHARD_ANCHOR_RE.search(body_nc):
            has_parent_context = bool(_PARENT_CHAIN_ANCHOR_RE.search(fn_text + body_nc))
            has_finalized_context = bool(_FINALIZED_ANCHOR_RE.search(fn_text + body_nc))
            has_unknown_anchor_error = bool(_UNKNOWN_FINAL_ANCHOR_ERR_RE.search(body_nc))

            if not (has_parent_context and has_finalized_context and has_unknown_anchor_error):
                hits.append({
                    "detector_id": DETECTOR_ID,
                    "severity": "medium",
                    "line": line,
                    "col": col,
                    "snippet": snippet_of(fn, source)[:220],
                    "message": (
                        f"fn `{name}` performs Sapling or Orchard anchor validation "
                        "without all Zebra contextual anchors: parent Chain lookup, "
                        "finalized ZebraDb lookup, and Unknown*Anchor rejection. "
                        "Review for accepting anchors outside earlier final treestates."
                    ),
                })

        if (
            "sprout" in body_nc.lower()
            and "joinsplit" in body_nc.lower()
            and _SPROUT_TREE_LOOKUP_RE.search(body_nc)
            and _SPROUT_INSERT_RE.search(body_nc)
            and not _has_root_anchor_binding_guard(body_nc)
        ):
            hits.append({
                "detector_id": DETECTOR_ID,
                "severity": "medium",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:220],
                "message": (
                    f"fn `{name}` inserts a Sprout treestate fetched by anchor "
                    "without an explicit tree.root() == anchor binding guard. "
                    "Review the anchor-keyed treestate map before using it for "
                    "contextual JoinSplit validation."
                ),
            })

    return hits

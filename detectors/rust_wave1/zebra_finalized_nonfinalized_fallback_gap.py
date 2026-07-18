"""
zebra_finalized_nonfinalized_fallback_gap.py

Flags Zebra-style acceptance helpers that do a cross-state fallback lookup
between non-finalized state and finalized state, but omit the sibling spent /
presence guard that makes the fallback safe.

Target shape:
  1. Acceptance-oriented function name (`validate_*`, `check_*`,
     `*_spend_*`, `*_duplicates_*`, `*_anchors_*`, `*refer_to*`).
  2. Body references both a non-finalized source (`parent_chain`,
     `non_finalized_*`, `chain`) and a finalized source
     (`finalized_state`, `finalized_chain`, `db`).
  3. A lookup falls back across state views via `.or_else(...)`.
  4. The body has no sibling spent/presence guard such as:
       - `spent_*.contains_key(...)`
       - `.spent_utxos.contains_key(...)`
       - `contains_*nullifier(...)`
       - `contains_*anchor(...)`

This is intentionally narrow. Zebra has many benign cross-state read helpers
that are documented as best-effort reads, not acceptance checks. We aim at the
context-sensitive validation shape where omitting the sibling guard can accept
stale or already-spent data.
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
    walk_no_nested_fn,
)


_ACCEPT_FN_RE = re.compile(
    r"^(?:validate|check|accept|reject|verify|ensure)"
    r"|(?:^|_)(?:spend|duplicate|duplicates|anchor|anchors)(?:_|$)"
    r"|refer_to",
    re.IGNORECASE,
)

_NON_FINALIZED_RE = re.compile(
    r"\b(?:parent_chain|non_finalized(?:_[A-Za-z0-9_]+)?|chain)\b"
)
_FINALIZED_RE = re.compile(r"\b(?:finalized_(?:state|chain)|db)\b")

_FALLBACK_RE = re.compile(
    r"(?:parent_chain|non_finalized[\w\.]*|chain(?:\.[A-Za-z_][A-Za-z0-9_]*)?)"
    r"[\s\S]{0,220}\.or_else\s*\(\s*\|\|\s*(?:finalized_(?:state|chain)|db)\.",
    re.IGNORECASE,
)
_REVERSE_FALLBACK_RE = re.compile(
    r"(?:finalized_(?:state|chain)|db(?:\.[A-Za-z_][A-Za-z0-9_]*)?)"
    r"[\s\S]{0,220}\.or_else\s*\(\s*\|\|\s*(?:parent_chain|non_finalized[\w\.]*|chain)\.",
    re.IGNORECASE,
)

_GUARD_PATTERNS = [
    r"spent_[A-Za-z0-9_]*\s*\.\s*contains_key\s*\(",
    r"\.spent_utxos\s*\.\s*contains_key\s*\(",
    r"contains_[A-Za-z0-9_]*nullifier\s*\(",
    r"contains_[A-Za-z0-9_]*anchor\s*\(",
    r"height_by_hash\s*\.\s*contains_key\s*\(",
    r"duplicate[A-Za-z0-9_]*",
]


def _has_cross_state_context(body_text: str) -> bool:
    return bool(_NON_FINALIZED_RE.search(body_text) and _FINALIZED_RE.search(body_text))


def _has_sibling_guard(body_text: str) -> bool:
    return any(re.search(pattern, body_text) for pattern in _GUARD_PATTERNS)


def _fallback_call_node(body, source: bytes):
    for node in walk_no_nested_fn(body):
        if node.type != "call_expression":
            continue
        call_text = text_of(node, source)
        if _FALLBACK_RE.search(call_text) or _REVERSE_FALLBACK_RE.search(call_text):
            return node
    return None


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue

        name = fn_name(fn, source)
        if not _ACCEPT_FN_RE.search(name):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        body_text = body_text_nocomment(body, source)
        if not _has_cross_state_context(body_text):
            continue

        fallback_node = _fallback_call_node(body, source)
        if fallback_node is None:
            continue

        if _has_sibling_guard(body_text):
            continue

        line, col = line_col(fallback_node)
        hits.append({
            "severity": "medium",
            "line": line,
            "col": col,
            "snippet": snippet_of(fallback_node, source),
            "message": (
                f"fn `{name}` performs a finalized/non-finalized fallback lookup "
                "without any sibling spent/presence guard. In Zebra-style "
                "state validation, cross-state acceptance of UTXOs / anchors / "
                "nullifiers must bind the fallback to the sibling chain view, "
                "or the lookup can accept context-sensitive stale data."
            ),
        })

    return hits

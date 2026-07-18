"""
cross_state_fallback_validation_gap_fire21.py

Fire21 Rust same-class lift for cross-state fallback validation gaps.

Flags validation or acceptance paths that combine finalized or trusted state
with non-finalized, cached, pending, or otherwise weaker state through a
fallback lookup, then consume the result as proof or consensus input without a
nearby finality, height, chain-context, or spent-state revalidation guard.

Confirmed source:
- zebra-finalized-nonfinalized-fallback-gap-positive

Class: cross-state-fallback-validation-gap.
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
    source_nocomment,
    text_of,
    walk_no_nested_fn,
)


DETECTOR_ID = "rust_wave1.cross_state_fallback_validation_gap_fire21"

_SOURCE_CONTEXT_RE = re.compile(
    r"\b(?:finali[sz]ed|non_?finali[sz]ed|trusted|canonical|pending|"
    r"cached|cache|proof|consensus|header|block|anchor|utxo|outpoint|"
    r"state_?root|chain_?id|height)\b",
    re.IGNORECASE,
)

_ACCEPT_NAME_RE = re.compile(
    r"^(?:validate|verify|check|accept|ensure|process|apply|commit|"
    r"prove|consume)"
    r"|(?:^|_)(?:proof|consensus|header|block|anchor|utxo|outpoint|"
    r"spend|state_?root|root|finality)(?:_|$)",
    re.IGNORECASE,
)

_ACCEPT_BODY_RE = re.compile(
    r"\b(?:verify_?(?:proof|consensus|header|block|state|root)|"
    r"accept_?(?:proof|header|block|root|consensus)|"
    r"commit_?(?:root|state|block|header)|"
    r"consume_?(?:proof|root|header|block)|"
    r"validate_?(?:proof|header|block|root|spend)|"
    r"Ok\s*\(|return\s+Some\s*\(|Accepted|Verified|ConsensusResult)\b",
    re.IGNORECASE,
)

_FINALIZED_STATE = (
    r"(?:finali[sz]ed(?:_[A-Za-z0-9_]+)?|trusted(?:_[A-Za-z0-9_]+)?|"
    r"canonical(?:_[A-Za-z0-9_]+)?|checkpoint(?:ed)?(?:_[A-Za-z0-9_]+)?|"
    r"safe(?:_[A-Za-z0-9_]+)?|stable(?:_[A-Za-z0-9_]+)?|"
    r"final_state|state_db|db)"
)
_WEAKER_STATE = (
    r"(?:non_?finali[sz]ed(?:_[A-Za-z0-9_]+)?|pending(?:_[A-Za-z0-9_]+)?|"
    r"cached(?:_[A-Za-z0-9_]+)?|cache(?:_[A-Za-z0-9_]+)?|"
    r"candidate(?:_[A-Za-z0-9_]+)?|untrusted(?:_[A-Za-z0-9_]+)?|"
    r"fork(?:_[A-Za-z0-9_]+)?|mempool(?:_[A-Za-z0-9_]+)?|"
    r"parent_chain|tip(?:_[A-Za-z0-9_]+)?|chain)"
)

_TRUSTED_TO_WEAKER_FALLBACK_RE = re.compile(
    rf"\b{_FINALIZED_STATE}\b[\s\S]{{0,320}}"
    rf"(?:\.or_else\s*\(|\.unwrap_or_else\s*\(|None\s*=>|else\s*\{{)"
    rf"[\s\S]{{0,220}}\b{_WEAKER_STATE}\b",
    re.IGNORECASE,
)
_WEAKER_TO_TRUSTED_FALLBACK_RE = re.compile(
    rf"\b{_WEAKER_STATE}\b[\s\S]{{0,320}}"
    rf"(?:\.or_else\s*\(|\.unwrap_or_else\s*\(|None\s*=>|else\s*\{{)"
    rf"[\s\S]{{0,220}}\b{_FINALIZED_STATE}\b",
    re.IGNORECASE,
)

_REVALIDATION_GUARD_RE = re.compile(
    r"(?is)("
    r"\b(?:ensure|verify|validate|check|revalidate|assert)_?"
    r"(?:finality|finalized|finalised|height|chain|context|network|"
    r"root|state|proof)\s*\(|"
    r"\b(?:is|was)_?finali[sz]ed\s*\(|"
    r"\b(?:height|block_height|root_height|anchor_height)\b"
    r"[^;{}]{0,100}(?:==|!=|<=|>=)"
    r"[^;{}]{0,100}\b(?:finali[sz]ed|trusted|expected|checkpoint|"
    r"context)\b|"
    r"\b(?:chain_?id|network_?id|context_?id)\b"
    r"[^;{}]{0,100}(?:==|!=)"
    r"[^;{}]{0,100}\b(?:expected|trusted|context|network|"
    r"consensus)\b|"
    r"\b[A-Za-z0-9_]*spent[A-Za-z0-9_]*\s*\.\s*"
    r"(?:contains_key|contains)\s*\(|"
    r"\bcontains_[A-Za-z0-9_]*(?:nullifier|anchor|outpoint|utxo)"
    r"\s*\("
    r")"
)


def _function_signature(fn, body, source: bytes) -> str:
    return source[fn.start_byte:body.start_byte].decode("utf-8", errors="replace")


def _has_accepting_context(name: str, signature: str, body: str) -> bool:
    joined = f"{name}\n{signature}\n{body}"
    return bool(_ACCEPT_NAME_RE.search(name) or _ACCEPT_BODY_RE.search(joined))


def _fallback_kind(text: str) -> str | None:
    if _TRUSTED_TO_WEAKER_FALLBACK_RE.search(text):
        return "trusted-to-weaker"
    if _WEAKER_TO_TRUSTED_FALLBACK_RE.search(text):
        return "weaker-to-trusted"
    return None


def _fallback_node(body, source: bytes):
    for node in walk_no_nested_fn(body):
        node_text = text_of(node, source)
        if _fallback_kind(node_text):
            return node
    return None


def _message(name: str, kind: str) -> str:
    if kind == "trusted-to-weaker":
        direction = "falls back from finalized or trusted state to weaker state"
    else:
        direction = "falls back across non-finalized and finalized state"
    return (
        f"fn `{name}` {direction} before accepting proof or consensus data "
        "without revalidating finality, height, chain context, or sibling "
        "spent-state; this is cross-state-fallback-validation-gap candidate "
        "evidence."
    )


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    if not _SOURCE_CONTEXT_RE.search(source_nocomment(source)):
        return hits

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        name = fn_name(fn, source)
        signature = _function_signature(fn, body, source)
        body_text = body_text_nocomment(body, source)
        if not _has_accepting_context(name, signature, body_text):
            continue

        kind = _fallback_kind(body_text)
        if kind is None:
            continue

        if _REVALIDATION_GUARD_RE.search(body_text):
            continue

        node = _fallback_node(body, source) or fn
        line, col = line_col(node)
        hits.append(
            {
                "detector_id": DETECTOR_ID,
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(node, source)[:220],
                "message": _message(name, kind),
            }
        )

    return hits

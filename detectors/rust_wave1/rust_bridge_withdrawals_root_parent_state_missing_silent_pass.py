"""
rust_bridge_withdrawals_root_parent_state_missing_silent_pass.py

Flags Rust bridge withdrawal finalizers that accept a parent-state hash or
parent header, then verify an attacker-supplied withdrawal or receipt root
without binding that root to the parent state being trusted.

This closes a bridge-proof-domain-bypass recall gap that is distinct from
the existing bridge message hash and generic proof-root digest detectors:
the missing domain here is the parent state coordinate, not a lane or chain
field in a replay key.
"""

from __future__ import annotations

import re

from _util import (
    body_text_nocomment,
    fn_body,
    fn_name,
    function_items,
    in_test_cfg,
    is_pub,
    line_col,
    snippet_of,
)


_FN_NAME_RE = re.compile(
    r"(?i)\b("
    r"finali[sz]e|process|prove|claim|withdraw|settle|release|execute|verify"
    r").*(withdraw|exit|claim|receipt|proof)"
)

_PARENT_STATE_CONTEXT_RE = re.compile(
    r"(?i)\b("
    r"parent_state(?:_hash|_root|_id)?|"
    r"parent_(?:hash|root|header|block|state)|"
    r"parent_header(?:_hash)?|"
    r"parent_block_hash|"
    r"trusted_parent|"
    r"known_parent"
    r")\b"
)

_WITHDRAWAL_ROOT_RE = re.compile(
    r"(?i)\b("
    r"withdrawal(?:s)?_root|"
    r"receipt_root|"
    r"message_root|"
    r"outbox_root|"
    r"storage_root|"
    r"proof_root|"
    r"root_claim|"
    r"state_root"
    r")\b"
)

_PROOF_MATERIAL_RE = re.compile(
    r"(?i)\b[A-Za-z0-9_]*(?:proof|merkle|leaf|receipt|withdrawal|message)"
    r"[A-Za-z0-9_]*\b"
)

_VERIFY_EXPR_RE = re.compile(
    r"(?i)\b(?:[A-Za-z0-9_]+::)?(?:"
    r"verify|verify_proof|verify_merkle|verify_merkle_proof|"
    r"check_proof|validate_proof|verify_root|verify_receipt|"
    r"merkle_verify|prove_withdrawal"
    r")\s*\([^;{}]{0,700}\)",
    re.DOTALL,
)

_PARENT_BOUND_RE = re.compile(
    r"(?i)\b("
    r"parent_state(?:_hash|_root|_id)?|"
    r"parent_(?:hash|root|header|block|state)|"
    r"parent_header(?:_hash)?|"
    r"parent_block_hash|"
    r"trusted_parent|"
    r"known_parent|"
    r"parent\s*\."
    r")"
)

_ROOT_PARENT_GUARD_RE = re.compile(
    r"(?is)("
    r"\b(?:withdrawal(?:s)?_root|receipt_root|message_root|outbox_root|"
    r"storage_root|proof_root|root_claim|state_root)\b"
    r"\s*(?:==|!=)\s*[^;\n{}]*"
    r"(?:parent_state|parent_header|parent_|trusted_parent|known_parent|parent\s*\.)"
    r"[^;\n{}]*"
    r"(?:withdrawal(?:s)?_root|receipt_root|message_root|outbox_root|"
    r"storage_root|proof_root|root_claim|state_root)"
    r"|"
    r"(?:parent_state|parent_header|parent_|trusted_parent|known_parent|parent\s*\.)"
    r"[^;\n{}]*"
    r"(?:withdrawal(?:s)?_root|receipt_root|message_root|outbox_root|"
    r"storage_root|proof_root|root_claim|state_root)"
    r"\s*(?:==|!=)\s*[^;\n{}]*"
    r"\b(?:withdrawal(?:s)?_root|receipt_root|message_root|outbox_root|"
    r"storage_root|proof_root|root_claim|state_root)\b"
    r"|"
    r"(?:assert_eq!|ensure!)\s*\([^;{}]*"
    r"(?:parent_state|parent_header|parent_|trusted_parent|known_parent|parent\s*\.)"
    r"[^;{}]*"
    r"(?:withdrawal(?:s)?_root|receipt_root|message_root|outbox_root|"
    r"storage_root|proof_root|root_claim|state_root)"
    r"[^;{}]*\)"
    r")"
)


def _unsafe_verify_exprs(body_text: str) -> list[str]:
    out: list[str] = []
    for match in _VERIFY_EXPR_RE.finditer(body_text):
        expr = match.group(0)
        if not _WITHDRAWAL_ROOT_RE.search(expr):
            continue
        if not _PROOF_MATERIAL_RE.search(expr):
            continue
        if _PARENT_BOUND_RE.search(expr):
            continue
        out.append(expr)
    return out


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        if not is_pub(fn, source):
            continue

        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        fn_text = source[fn.start_byte:fn.end_byte].decode("utf-8", errors="replace")
        body_nc = body_text_nocomment(body, source)
        if not _PARENT_STATE_CONTEXT_RE.search(fn_text):
            continue
        if not _WITHDRAWAL_ROOT_RE.search(body_nc):
            continue
        if not _PROOF_MATERIAL_RE.search(body_nc):
            continue
        if _ROOT_PARENT_GUARD_RE.search(body_nc):
            continue

        unsafe_exprs = _unsafe_verify_exprs(body_nc)
        if not unsafe_exprs:
            continue

        line, col = line_col(fn)
        hits.append(
            {
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:220],
                "message": (
                    f"pub fn `{name}` checks parent-state context but verifies "
                    f"a withdrawal or receipt root without binding it to that "
                    f"parent state. A root from another parent state can pass "
                    f"the withdrawal proof path silently."
                ),
            }
        )

    return hits

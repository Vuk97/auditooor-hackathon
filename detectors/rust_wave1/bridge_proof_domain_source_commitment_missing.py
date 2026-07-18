"""
bridge_proof_domain_source_commitment_missing.py

Flags Rust bridge proof or replay digest verifiers that accept source
commitment fields such as a parachain id, source export id, source txid,
source chain, or commitment hash, but then verify or build the proof/replay
expression without binding any of those fields into it.

Confirmed source anchor:
- detectors/fixtures/bridge_proof_domain_bypass_snowbridge_commitment/positive.sol

This detector is narrower than the generic proof-root domain detector. It
requires explicit source commitment fields and a proof, leaf, root, message,
payload, or replay digest path where every candidate expression omits those
source fields.
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
    r"(?i)("
    r"(verify|validate|check|process|finalize|submit|relay|prove|settle)"
    r".*(bridge|proof|root|commitment|receipt|message|header|packet)"
    r"|verify_.*commitment"
    r"|process_.*commitment"
    r"|bridge_.*(digest|hash|message|packet|payload)"
    r"|message_.*(digest|hash)"
    r"|hash_.*message"
    r")"
)

_BRIDGE_PROOF_RE = re.compile(
    r"(?i)("
    r"\bbridge\b|\bbridge_|\bcross[_-]?chain\b|\bbeefy\b|\bmmr\b|"
    r"\bparachain\b|\bpara[_-]?id\b|\bmerkle\b|\bproof\b|\broot\b|"
    r"\bcommitment\b|\bleaf\b|\bheader\b|\bmessage\b|\bpayload\b|"
    r"\bdigest\b|\bhash\b"
    r")"
)

_SOURCE_FIELD_RE = re.compile(
    r"\b("
    r"encoded_para_id|encoded_paraid|para_id|parachain_id|"
    r"source_commitment|export_commitment|commitment_hash|commitment|"
    r"source_export|export_id|source_txid|source_tx_id|source_receipt|"
    r"source_root|origin_root|source_chain|src_chain|origin_chain"
    r")\b",
    re.IGNORECASE,
)

_PROOF_MATERIAL_RE = re.compile(
    r"(?i)\b("
    r"proof|leaf|leaf_hash|root|state_root|storage_root|header_root|"
    r"parachain_heads_root|parachain_head_hash|mmr|merkle|receipt|header|"
    r"payload|payload_hash|message|message_hash|packet|nonce|sequence"
    r")\b"
)

_CANDIDATE_EXPR_RE = re.compile(
    r"(?is)\b(?:[A-Za-z0-9_]+\s*\.\s*)?(?:"
    r"verify_mmr_leaf_proof|verify_merkle_proof|verify_proof|verify_root|"
    r"verify_commitment|compute_root|create_mmr_leaf|merkle_verify|"
    r"keccak256|sha256|blake2(?:b|s)?|hash|digest"
    r")\s*\([^;{}]{0,720}\)"
)

_CONSUME_SOURCE_RE = re.compile(
    r"(?is)\b(?:consumed|processed|used|spent|seen|settled|executed|commitments?)"
    r"[A-Za-z0-9_]*\s*(?:\.insert|\.set|\[|\.get|\.contains)"
    r"[^;{}]{0,360}\b("
    r"encoded_para_id|encoded_paraid|para_id|parachain_id|"
    r"source_commitment|export_commitment|commitment_hash|commitment|"
    r"source_export|export_id|source_txid|source_tx_id|source_receipt"
    r")\b"
)


def _source_fields(text: str) -> set[str]:
    return {match.group(1).lower() for match in _SOURCE_FIELD_RE.finditer(text)}


def _field_in_expr(field: str, expr: str) -> bool:
    return re.search(rf"\b{re.escape(field)}\b", expr, re.IGNORECASE) is not None


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
        if not _BRIDGE_PROOF_RE.search(fn_text):
            continue

        visible_source_fields = _source_fields(fn_text)
        if not visible_source_fields:
            continue
        if _CONSUME_SOURCE_RE.search(body_nc):
            continue

        candidate_exprs = [
            match.group(0)
            for match in _CANDIDATE_EXPR_RE.finditer(body_nc)
            if _PROOF_MATERIAL_RE.search(match.group(0))
        ]
        if not candidate_exprs:
            continue

        binds_source_field = any(
            _field_in_expr(field, expr)
            for field in visible_source_fields
            for expr in candidate_exprs
        )
        if binds_source_field:
            continue

        line, col = line_col(fn)
        hits.append(
            {
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:220],
                "message": (
                    f"pub fn `{name}` receives source commitment fields "
                    f"({', '.join(sorted(visible_source_fields))}) but its "
                    f"proof verifier or digest path does not bind any of "
                    f"them. A bridge proof or replay digest can be accepted "
                    f"without being scoped to the source commitment."
                ),
            }
        )

    return hits

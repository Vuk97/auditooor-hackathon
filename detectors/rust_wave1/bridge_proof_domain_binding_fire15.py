"""
bridge_proof_domain_binding_fire15.py

Flags Rust bridge proof paths where a proof digest, verification call, or
recipient-byte handler omits the domain fields that scope the authorization.

Fire15 lifts the Solidity bridge-proof-domain-bypass class into Rust and
generalizes three confirmed Rust misses:
- bridge_proof_domain_companion_fire12_positive
- bridge_proof_domain_source_commitment_missing_positive
- bridge_recipient_non_20_byte_payload_silently_burns_positive
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


DETECTOR_ID = "rust_wave1.bridge_proof_domain_binding_fire15"

_STRING_RE = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')

_BRIDGE_CONTEXT_RE = re.compile(
    r"(?i)\b("
    r"bridge|cross[_-]?chain|gateway|portal|relay|relayer|route|lane|"
    r"proof|merkle|root|receipt|signal|message|attestation|commitment|"
    r"payload|packet|recipient|receiver"
    r")\b"
)

_FN_CONTEXT_RE = re.compile(
    r"(?i)("
    r"(verify|validate|check|consume|process|finalize|submit|relay|"
    r"prove|settle|claim|release|redeem|withdraw|payout)"
    r".*(bridge|cross|proof|root|commitment|receipt|message|header|"
    r"packet|payload|recipient|receiver|signal)"
    r"|bridge.*(proof|root|verify|consume|settle|message|digest|hash|"
    r"payload|recipient|receiver|transfer)"
    r"|proof.*(root|verify|consume|settle|release)"
    r"|message.*(hash|digest|verify|process)"
    r"|hash_.*message"
    r")"
)

_PROOF_OR_MESSAGE_RE = re.compile(
    r"(?i)\b("
    r"proof|proof_root|root|state_root|storage_root|header_root|"
    r"receipt_root|commitment_root|leaf|leaf_hash|proof_hash|"
    r"message_hash|payload_hash|commitment|receipt|header|mmr|merkle|"
    r"signal|signal_hash|attestation|payload|packet|nonce|sequence"
    r")\b"
)

_CANDIDATE_EXPR_RE = re.compile(
    r"(?is)\b(?:[A-Za-z0-9_]+\s*(?:::|\.)\s*)?(?:"
    r"verify_mmr_leaf_proof|verify_merkle_proof|verify_proof|"
    r"verify_root|verify_commitment|verify_message|verify_signal|"
    r"verify_receipt|verify_attestation|check_proof|validate_proof|"
    r"validate_message|consume_proof|compute_root|create_mmr_leaf|"
    r"message_digest|message_hash|replay_key|keccak256|sha256|"
    r"blake2(?:b|s)?|blake3|hash|digest"
    r")\s*\([^;{}]{0,1100}\)"
)

_CUSTODY_OR_CONSUME_RE = re.compile(
    r"(?is)\b("
    r"release|release_to|withdraw|payout|pay|credit|credit_to|mint|"
    r"mint_to|transfer|transfer_to|send_to|burn|burn_from|"
    r"mark_consumed|mark_processed|consume_message|set_consumed"
    r")\s*\(|"
    r"\.\s*(?:release|release_to|withdraw|payout|pay|credit|credit_to|"
    r"mint|mint_to|transfer|transfer_to|send_to|burn|burn_from|insert|"
    r"set)\s*\("
)

_FIELD_GROUP_PATTERNS = (
    (
        "lane",
        re.compile(r"\b(?:lane(?:_id)?|channel(?:_id)?|route(?:_id)?)\b", re.I),
    ),
    (
        "source",
        re.compile(
            r"\b(?:source_chain|src_chain|from_chain|origin_chain|"
            r"source_domain|src_domain|origin_domain|remote_domain|"
            r"encoded_para_id|encoded_paraid|para_id|parachain_id|"
            r"source_export|export_id|source_txid|source_tx_id|"
            r"source_receipt|source_root|origin_root)\b",
            re.I,
        ),
    ),
    (
        "destination",
        re.compile(
            r"\b(?:destination_chain|dest_chain|dst_chain|target_chain|"
            r"local_chain|destination_domain|dest_domain|dst_domain|"
            r"target_domain|local_domain|destination_id|dest_id|dst_id)\b",
            re.I,
        ),
    ),
    (
        "commitment",
        re.compile(
            r"\b(?:source_commitment|export_commitment|commitment_hash|"
            r"commitment|proof_commitment)\b",
            re.I,
        ),
    ),
    (
        "recipient",
        re.compile(
            r"\b(?:account|payee|recipient|receiver|beneficiary|"
            r"destination_account|payout_account|to_addr|to_address)\b",
            re.I,
        ),
    ),
    (
        "amount",
        re.compile(
            r"\b(?:payout|amount|value|quantity|qty|token_amount|"
            r"release_amount|withdraw_amount|mint_amount)\b",
            re.I,
        ),
    ),
    (
        "asset",
        re.compile(
            r"\b(?:token_id|asset_id|nft_id|coin_id|denom|currency|"
            r"asset|token)\b",
            re.I,
        ),
    ),
    (
        "application",
        re.compile(
            r"\b(?:application_domain|app_domain|receiver_domain|"
            r"export_domain|app_id|namespace)\b",
            re.I,
        ),
    ),
    (
        "verifier",
        re.compile(
            r"\b(?:verifying_contract|verifier_domain|domain_separator|"
            r"domain_id|chain_id|chainid|network_id|client_id|"
            r"light_client_id|ref_client_id)\b",
            re.I,
        ),
    ),
)

_RECIPIENT_PARAM_RE = re.compile(
    r"(?is)\b(?:recipient|receiver|to|beneficiary|payload|message|msg|"
    r"packet|body|raw_payload|receipt)[A-Za-z0-9_]*\s*:\s*"
    r"(?:&?\s*\[\s*u8\s*\]|Vec\s*<\s*u8\s*>|Bytes|Binary|"
    r"&\s*Vec\s*<\s*u8\s*>)"
)

_WEAK_RECIPIENT_LEN_RE = re.compile(
    r"(?is)("
    r"\.len\s*\(\s*\)\s*(?:>|<=|<)\s*20|"
    r"20\s*(?:<|>=|>)\s*[A-Za-z0-9_\.]+\s*\.len\s*\(\s*\)|"
    r"\.min\s*\(\s*20\s*\)|"
    r"copy_from_slice\s*\([^;\n]*(?:copy_len|min\s*\(|\.\.copy_len)|"
    r"addr\s*\[\s*\.\.\s*copy_len\s*\]"
    r")"
)

_EXACT_RECIPIENT_LEN_RE = re.compile(
    r"(?is)("
    r"\.len\s*\(\s*\)\s*(?:==|!=)\s*20|"
    r"20\s*(?:==|!=)\s*[A-Za-z0-9_\.]+\s*\.len\s*\(\s*\)|"
    r"try_into\s*\(\s*\)\s*\?|"
    r"<\s*\[\s*u8\s*;\s*20\s*\]\s*>::\s*try_from\s*\(|"
    r"validate_[A-Za-z0-9_]*(?:exact|recipient|receiver|address)"
    r"[A-Za-z0-9_]*(?:20|len|length)"
    r")"
)


def _blank(match: re.Match[str]) -> str:
    return "".join("\n" if char == "\n" else " " for char in match.group(0))


def _strip_strings(text: str) -> str:
    return _STRING_RE.sub(_blank, text)


def _signature_text(fn, body, source: bytes) -> str:
    return source[fn.start_byte:body.start_byte].decode("utf-8", errors="replace")


def _field_groups(text: str) -> set[str]:
    return {name for name, pattern in _FIELD_GROUP_PATTERNS if pattern.search(text)}


def _candidate_exprs(text: str) -> list[str]:
    return [
        match.group(0)
        for match in _CANDIDATE_EXPR_RE.finditer(text)
        if _PROOF_OR_MESSAGE_RE.search(match.group(0))
    ]


def _first_missing_binding(
    expressions: list[str],
    visible_fields: set[str],
) -> set[str] | None:
    if any(visible_fields <= _field_groups(expr) for expr in expressions):
        return None

    best_expr = max(expressions, key=lambda expr: len(_field_groups(expr)))
    omitted = visible_fields - _field_groups(best_expr)
    return omitted or None


def _looks_like_bridge_recipient_helper(name: str, fn_text: str, file_text: str) -> bool:
    if not _BRIDGE_CONTEXT_RE.search(file_text):
        return False
    if not re.search(r"(?i)(recipient|receiver|address|payload|bridge|transfer)", name):
        return False
    return _RECIPIENT_PARAM_RE.search(fn_text) is not None


def _recipient_length_hit(name: str, fn_text: str, body_text: str, file_text: str) -> bool:
    if not _looks_like_bridge_recipient_helper(name, fn_text, file_text):
        return False
    if _EXACT_RECIPIENT_LEN_RE.search(body_text):
        return False
    return _WEAK_RECIPIENT_LEN_RE.search(body_text) is not None


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    file_text = source.decode("utf-8", errors="replace")
    file_text_nc = _strip_strings(file_text)

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        if not is_pub(fn, source):
            continue

        name = fn_name(fn, source)
        body = fn_body(fn)
        if body is None:
            continue

        signature = _signature_text(fn, body, source)
        body_nc = _strip_strings(body_text_nocomment(body, source))
        fn_text = f"{signature}\n{body_nc}"

        if _recipient_length_hit(name, fn_text, body_nc, file_text_nc):
            line, col = line_col(fn)
            hits.append(
                {
                    "detector_id": DETECTOR_ID,
                    "severity": "high",
                    "line": line,
                    "col": col,
                    "snippet": snippet_of(fn, source)[:220],
                    "message": (
                        f"pub fn `{name}` accepts bridge recipient bytes with "
                        "only max-length or truncating validation. Non-20-byte "
                        "recipient payloads can be decoded into a different "
                        "destination domain."
                    ),
                }
            )
            continue

        if not _FN_CONTEXT_RE.search(name):
            continue
        if not _BRIDGE_CONTEXT_RE.search(fn_text):
            continue
        if not (
            _PROOF_OR_MESSAGE_RE.search(body_nc)
            and (_CUSTODY_OR_CONSUME_RE.search(body_nc) or _CANDIDATE_EXPR_RE.search(body_nc))
        ):
            continue

        # Digest/domain checks should bind the fields supplied to this entrypoint.
        # Fields nested inside an already-hashed message struct are not independent
        # top-level digest coordinates.
        visible_fields = _field_groups(signature)
        if not visible_fields:
            continue

        expressions = _candidate_exprs(body_nc)
        if not expressions:
            continue

        omitted = _first_missing_binding(expressions, visible_fields)
        if omitted is None:
            continue

        line, col = line_col(fn)
        hits.append(
            {
                "detector_id": DETECTOR_ID,
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:220],
                "message": (
                    f"pub fn `{name}` verifies or consumes bridge proof, "
                    f"message, or commitment material without binding visible "
                    f"domain fields into any checked digest: "
                    f"{', '.join(sorted(omitted))}. A proof valid in one "
                    "source, destination, recipient, payout, or commitment "
                    "context may authorize another context."
                ),
            }
        )

    return hits

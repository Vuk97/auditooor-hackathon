"""
signature_chain_replay_fire38.py

Rust detector lift for bridge execution, retry settlement, and cached chain
signature replay paths.

Fire38 targets public bridge or settlement entrypoints that verify a signature
over calldata, award, or payload bytes and then execute, settle, credit, or
record state while visible chain, endpoint, nonce, settlement, or contract
purpose fields remain outside the authenticated digest or transcript.

Source refs:
- reports/detector_lift_fire37_20260605/post_priorities_rust.md
- detectors/rust_wave1/signature_participant_set_domain_fire37.py
- reference/patterns.dsl/signature-replay-cross-domain.yaml
- r94-loop-bridge-execute-calldata-missing-chainid-replay-positive
- r94-loop-bridge-retry-settlement-award-replay-positive

verification_tier: tier-3-synthetic-taxonomy-anchored
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


DETECTOR_ID = "rust_wave1.signature_chain_replay_fire38"
ATTACK_CLASS = "signature-replay-cross-domain"
VERIFICATION_TIER = "tier-3-synthetic-taxonomy-anchored"

_STRING_RE = re.compile(r"(?s)b?r#*\".*?\"#*|b?'(?:\\.|[^'\\])+'")

_CHAIN_SIG_CONTEXT_RE = re.compile(
    r"(?i)\b("
    r"bridge|cross_?chain|gateway|router|route|endpoint|channel|lane|"
    r"message|packet|payload|calldata|execute|dispatch|retry|settlement|"
    r"settle|award|claim|withdraw|release|signature|signed|verify|"
    r"attestation|digest|transcript|domain|nonce|chain_?id|chainid"
    r")\b"
)

_ENTRY_FN_RE = re.compile(
    r"(?i)("
    r"(execute|dispatch|process|receive|handle|relay|retry|settle|"
    r"settlement|claim|release|withdraw|finalize|complete|redeem).*"
    r"(bridge|message|packet|payload|calldata|signature|signed|digest|"
    r"attestation|settlement|award|claim)"
    r"|"
    r"(bridge|message|packet|payload|calldata|signature|signed|digest|"
    r"attestation|settlement|award|claim).*"
    r"(execute|dispatch|process|receive|handle|relay|retry|settle|"
    r"claim|release|withdraw|finalize|complete|redeem)"
    r")"
)

_AUTH_BUILD_RE = re.compile(
    r"(?is)\b("
    r"Transcript::new|merlin::Transcript|SigningTranscript|SigningContext|"
    r"signing_context|signing_transcript|new_transcript|build_transcript|"
    r"transcript_bytes|challenge_bytes|challenge_scalar|challenge|"
    r"compute_challenge|keccak256|sha256|sha3|blake2b|blake2s|blake3|"
    r"poseidon|hash|hash_bytes|digest|digest_bytes|message_hash|"
    r"payload_hash|call_hash|settlement_hash|to_signing_bytes|"
    r"signing_bytes|sign_bytes|message_bytes"
    r")\b"
    r"|[A-Za-z0-9_]+::digest\s*\("
    r"|Message::from_digest\s*\("
    r"|\.finalize\s*\("
)

_DIRECT_HASH_CALL_RE = re.compile(
    r"(?is)\b(?:keccak256|sha256|sha3|blake2b|blake2s|blake3|poseidon|"
    r"hash|hash_bytes|digest|digest_bytes|message_hash|payload_hash|"
    r"call_hash|settlement_hash|to_signing_bytes|signing_bytes|"
    r"sign_bytes|message_bytes)\s*\((?P<arg>[^;{}]{0,2200})\)"
    r"|[A-Za-z0-9_]+::digest\s*\((?P<assoc_arg>[^;{}]{0,2200})\)"
    r"|Message::from_digest\s*\((?P<message_arg>[^;{}]{0,1200})\)"
)

_LET_ASSIGN_RE = re.compile(
    r"(?is)\blet\s+(?:mut\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*(?::[^=;]+)?=\s*(?P<expr>[^;]{0,3000});"
)

_AUTH_WRITE_RE = re.compile(
    r"(?is)\b(?P<buf>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*"
    r"(?P<method>"
    r"append_message|append_u64|append_i64|append_u32|append_i32|"
    r"append_u128|append_bytes|append_public_key|commit_bytes|"
    r"append|extend_from_slice|extend|update|chain_update|input|absorb"
    r")\s*\((?P<arg>[^;{}]{0,1800})\)"
)

_PUSH_CALL_RE = re.compile(
    r"(?is)\b(?P<buf>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*"
    r"push\s*\((?P<arg>[^;{}]{0,900})\)"
)

_VERIFY_CALL_RE = re.compile(
    r"(?is)"
    r"(?:\b[A-Za-z0-9_:<>]+\s*(?:::|\.)\s*)?"
    r"(?P<fn>"
    r"verify_signature|verify_sig|verify_prehashed|verify_digest|"
    r"verify_transcript|verify_message|verify_payload|verify_batch|"
    r"verify_attestation|verify_bridge_message|verify_settlement|"
    r"ed25519_verify|sr25519_verify|ecdsa_verify|secp256k1_verify|"
    r"secp256r1_verify|schnorr_verify|bls_verify|recover_signature|"
    r"recover|is_valid_signature|authenticate_signature|verify"
    r")\s*\((?P<args>[^;{}]{0,2400})\)"
)

_PAYLOAD_MATERIAL_RE = re.compile(
    r"(?i)\b("
    r"message|msg|payload|payload_hash|call|calldata|call_data|recipient|"
    r"receiver|amount|value|asset|asset_id|token|award|award_amount|"
    r"payout|params|order|withdrawal|transfer|claim|permit|intent|"
    r"request|operation|instruction|data|sign_bytes|signing_bytes|"
    r"transcript_bytes|settlement|settlement_id"
    r")\b"
)

_STATE_EFFECT_RE = re.compile(
    r"(?is)"
    r"\b(?:transfer|safe_transfer|mint|burn|withdraw|release|claim|redeem|"
    r"settle|settle_award|credit|debit|execute|execute_call|dispatch|"
    r"dispatch_call|approve|fulfill|finalize|complete|pay_out|award)\s*\("
    r"|\.insert\s*\("
    r"|\.save\s*\("
    r"|\.set\s*\("
    r"|\.remove\s*\("
    r"|\[[^\]]+\]\s*=\s*(?:true|1)"
)

_SAFE_HELPER_RE = re.compile(
    r"(?i)\b("
    r"domain_separated|domain_bound|domain_bound_digest|"
    r"domain_bound_transcript|bind_domain|bind_chain|bind_endpoint|"
    r"bind_channel|bind_lane|bind_nonce|bind_nonce_context|"
    r"bind_settlement|bind_settlement_id|bind_purpose|bind_contract|"
    r"bind_verifying_contract|bind_signature_domain|bind_signature_scope|"
    r"scoped_signature_digest|scoped_transcript|replay_bound_transcript|"
    r"route_bound_key|verify_with_domain|verify_with_scope|"
    r"ensure_domain|ensure_chain|ensure_endpoint|ensure_channel|"
    r"ensure_nonce|ensure_settlement|ensure_purpose|ensure_contract"
    r")\s*\("
)

_SCOPE_FIELDS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "chain_id",
        re.compile(
            r"(?i)\b("
            r"chain_?id|chainid|network_?id|fork_?id|genesis_?hash|"
            r"source_?chain_?id|src_?chain_?id|origin_?chain_?id|"
            r"from_?chain_?id|destination_?chain_?id|dest_?chain_?id|"
            r"dst_?chain_?id|target_?chain_?id|source_?chain|"
            r"src_?chain|origin_?chain|from_?chain|destination_?chain|"
            r"dest_?chain|dst_?chain|target_?chain|"
            r"remote_?chain|local_?chain|para_?id|parachain_?id"
            r")\b"
        ),
    ),
    (
        "endpoint",
        re.compile(
            r"(?i)\b("
            r"endpoint|endpoint_?id|src_?endpoint|dst_?endpoint|"
            r"channel|channel_?id|source_?channel|destination_?channel|"
            r"src_?channel|dst_?channel|lane|lane_?id|route|route_?id|"
            r"port_?id|bridge_?endpoint"
            r")\b"
        ),
    ),
    (
        "nonce_context",
        re.compile(
            r"(?i)\b("
            r"nonce|message_?nonce|packet_?nonce|sequence|seq|"
            r"replay_?nonce|retry_?nonce|claim_?nonce|execution_?nonce|"
            r"nonce_?context|ordered_?nonce"
            r")\b"
        ),
    ),
    (
        "settlement_id",
        re.compile(
            r"(?i)\b("
            r"settlement_?id|settlement_?nonce|settlement_?key|"
            r"settlement_?epoch|settlement_?round|award_?id|payout_?id|"
            r"claim_?id|request_?id|operation_?id|transfer_?id|message_?id"
            r")\b"
        ),
    ),
    (
        "purpose_domain",
        re.compile(
            r"(?i)\b("
            r"purpose|purpose_?tag|purpose_?domain|action|method|"
            r"operation|selector|intent_?type|permit_?type|call_?kind|"
            r"entry_?point|instruction_?tag|message_?type|domain_?separator|"
            r"domain_?id|domain_?tag|domain_?salt|domain_?hash|namespace|"
            r"protocol_?id|app_?id|scope_?id"
            r")\b"
        ),
    ),
    (
        "contract_domain",
        re.compile(
            r"(?i)\b("
            r"verifying_?contract|contract_?address|current_?contract|"
            r"target_?contract|bridge_?address|gateway_?address|program_?id|"
            r"app_?address|application_?domain"
            r")\b"
        ),
    ),
)

_LOAD_BEARING_FIELDS = {
    "chain_id",
    "endpoint",
    "nonce_context",
    "settlement_id",
    "purpose_domain",
    "contract_domain",
}


def _blank(match: re.Match[str]) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in match.group(0))


def _strip_strings(text: str) -> str:
    return _STRING_RE.sub(_blank, text)


def _signature_text(fn, body, source: bytes) -> str:
    return source[fn.start_byte:body.start_byte].decode("utf-8", errors="replace")


def _field_groups(text: str) -> set[str]:
    clean = _strip_strings(text)
    return {name for name, pattern in _SCOPE_FIELDS if pattern.search(clean)}


def _assignments(body: str) -> dict[str, str]:
    return {
        match.group("name"): match.group("expr")
        for match in _LET_ASSIGN_RE.finditer(body)
    }


def _auth_writes(body: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for match in _AUTH_WRITE_RE.finditer(body):
        out.setdefault(match.group("buf"), []).append(match.group("arg"))
    for match in _PUSH_CALL_RE.finditer(body):
        out.setdefault(match.group("buf"), []).append(match.group("arg"))
    return out


def _expand_expr(
    expr: str,
    assignments: dict[str, str],
    auth_writes: dict[str, list[str]],
) -> list[str]:
    parts = [expr]
    seen = {expr}
    changed = True

    while changed and len(parts) < 140:
        changed = False
        for item in list(parts):
            for name, assigned in assignments.items():
                if assigned in seen:
                    continue
                if re.search(rf"\b{re.escape(name)}\b", item):
                    parts.append(assigned)
                    seen.add(assigned)
                    changed = True
            for name, writes in auth_writes.items():
                if not re.search(rf"\b{re.escape(name)}\b", item):
                    continue
                for write in writes:
                    if write in seen:
                        continue
                    parts.append(write)
                    seen.add(write)
                    changed = True

    return parts


def _authenticated_input_text(body: str) -> str:
    assignments = _assignments(body)
    auth_writes = _auth_writes(body)
    inputs: list[str] = []

    for match in _AUTH_WRITE_RE.finditer(body):
        inputs.extend(_expand_expr(match.group("arg"), assignments, auth_writes))
    for match in _PUSH_CALL_RE.finditer(body):
        inputs.extend(_expand_expr(match.group("arg"), assignments, auth_writes))
    for match in _DIRECT_HASH_CALL_RE.finditer(body):
        arg = (
            match.group("arg")
            or match.group("assoc_arg")
            or match.group("message_arg")
            or ""
        )
        inputs.extend(_expand_expr(arg, assignments, auth_writes))
    for match in _VERIFY_CALL_RE.finditer(body):
        inputs.extend(_expand_expr(match.group("args"), assignments, auth_writes))
    for expr in assignments.values():
        if _AUTH_BUILD_RE.search(expr):
            inputs.extend(_expand_expr(expr, assignments, auth_writes))

    return "\n".join(inputs)


def _is_chain_replay_candidate(name: str, signature: str, body: str) -> bool:
    context = f"{name}\n{signature}\n{body}"
    if not (_ENTRY_FN_RE.search(name) or _CHAIN_SIG_CONTEXT_RE.search(context)):
        return False
    if not (_AUTH_BUILD_RE.search(body) and _VERIFY_CALL_RE.search(body)):
        return False
    if not _STATE_EFFECT_RE.search(body):
        return False
    if _SAFE_HELPER_RE.search(body):
        return False
    return True


def _missing_scope_fields(signature: str, body: str) -> set[str]:
    visible = _field_groups(f"{signature}\n{body}")
    if not (visible & _LOAD_BEARING_FIELDS):
        return set()

    auth_inputs = _authenticated_input_text(body)
    if not (auth_inputs.strip() and _PAYLOAD_MATERIAL_RE.search(auth_inputs)):
        return set()

    bound = _field_groups(auth_inputs)
    missing = visible - bound
    if not (missing & _LOAD_BEARING_FIELDS):
        return set()
    return missing


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        if not is_pub(fn, source):
            continue

        name = fn_name(fn, source)
        body_node = fn_body(fn)
        if body_node is None:
            continue

        signature = _signature_text(fn, body_node, source)
        body = _strip_strings(body_text_nocomment(body_node, source))
        if not _is_chain_replay_candidate(name, signature, body):
            continue

        missing = _missing_scope_fields(signature, body)
        if not missing:
            continue

        line, col = line_col(fn)
        hits.append(
            {
                "detector_id": DETECTOR_ID,
                "attack_class": ATTACK_CLASS,
                "verification_tier": VERIFICATION_TIER,
                "severity": "high",
                "file": filepath,
                "line": line,
                "col": col,
                "fn_name": name,
                "snippet": snippet_of(fn, source)[:240],
                "message": (
                    f"pub fn `{name}` verifies bridge or settlement "
                    "signature bytes that omit replay-scope binding for "
                    f"{', '.join(sorted(missing))}. Bind chain id, endpoint, "
                    "nonce context, settlement id, contract address, and "
                    "purpose domain into the signed digest or transcript "
                    f"before executing or settling. Class: {ATTACK_CLASS}."
                ),
            }
        )

    return hits

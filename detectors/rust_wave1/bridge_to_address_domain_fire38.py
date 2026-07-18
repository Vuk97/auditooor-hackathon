"""
bridge_to_address_domain_fire38.py

Rust detector lift for bridge proof verification paths that accept payout,
dispatch, destination, lane, source commitment, or consumed-message fields from
request material but leave those fields outside the verified proof digest.

Fire38 is seeded from:
- oversized-toaddress-in-sendfrom-breaks-layerzero-channel-positive
- bridge-beefy-commitment-domain-fire37-positive
- reports/detector_lift_fire37_20260605/post_priorities_rust.md
- detectors/rust_wave1/bridge_beefy_commitment_domain_fire37.py
- reference/patterns.dsl/bridge-proof-domain-bypass-umbrella.yaml

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


DETECTOR_ID = "rust_wave1.bridge_to_address_domain_fire38"
ATTACK_CLASS = "bridge-proof-domain-bypass"
VERIFICATION_TIER = "tier-3-synthetic-taxonomy-anchored"

_STRING_RE = re.compile(r"(?s)b?r#*\".*?\"#*|b?'(?:\\.|[^'\\])+'")

_BRIDGE_CONTEXT_RE = re.compile(
    r"(?i)\b("
    r"bridge|cross[_-]?chain|gateway|portal|router|route|channel|lane|"
    r"light[_-]?client|verifier|verification|proof|merkle|storage[_-]?proof|"
    r"state[_-]?root|commitment|message|packet|dispatch|settlement|"
    r"withdrawal|payout|release|claim|destination|recipient"
    r")\b"
)

_ENTRY_FN_RE = re.compile(
    r"(?i)("
    r"(finalize|claim|release|settle|process|execute|receive|dispatch|"
    r"relay|prove|verify|consume|payout|pay|withdraw)"
    r".*(bridge|transfer|message|packet|proof|claim|withdrawal|dispatch|payout)"
    r"|"
    r"(bridge|transfer|message|packet|proof|claim|withdrawal|dispatch|payout)"
    r".*(finalize|claim|release|settle|process|execute|receive|dispatch|"
    r"relay|prove|verify|consume|payout|pay|withdraw)"
    r")"
)

_PROOF_MATERIAL_RE = re.compile(
    r"(?i)\b("
    r"proof|proof[_-]?digest|proof[_-]?hash|payload|payload[_-]?hash|"
    r"message[_-]?hash|message[_-]?commitment|commitment|commitment[_-]?hash|"
    r"source[_-]?commitment|source[_-]?root|root|state[_-]?root|"
    r"leaf|leaf[_-]?hash|receipt|packet|header|merkle|nodes|signature|sig"
    r")\b"
)

_HASH_BUILD_RE = re.compile(
    r"(?is)\b(?:"
    r"(?:[A-Za-z_][A-Za-z0-9_:]*::)?"
    r"(?:keccak256|sha256|sha3|blake2_?256|blake2b|blake2s|blake3|"
    r"twox_?256|poseidon|hash|hash_bytes|digest|digest_bytes|"
    r"proof_digest|commitment_hash|leaf_hash|payload_hash|message_hash|"
    r"transcript_hash)"
    r")\s*\("
    r"|[A-Za-z0-9_]+::digest\s*\("
    r"|\.finalize\s*\("
)

_DIRECT_HASH_CALL_RE = re.compile(
    r"(?is)\b(?:"
    r"(?:[A-Za-z_][A-Za-z0-9_:]*::)?"
    r"(?:keccak256|sha256|sha3|blake2_?256|blake2b|blake2s|blake3|"
    r"twox_?256|poseidon|hash|hash_bytes|digest|digest_bytes|"
    r"proof_digest|commitment_hash|leaf_hash|payload_hash|message_hash|"
    r"transcript_hash)"
    r")\s*\((?P<arg>[^;{}]{0,2600})\)"
    r"|[A-Za-z0-9_]+::digest\s*\((?P<assoc_arg>[^;{}]{0,2600})\)"
)

_VERIFY_RE = re.compile(
    r"(?is)\b(?:[A-Za-z0-9_]+(?:::|\.)\s*)?("
    r"verify_bridge_proof|verify_message_proof|verify_transfer_proof|"
    r"verify_packet_proof|verify_claim_proof|verify_withdrawal_proof|"
    r"verify_commitment|verify_message_commitment|verify_source_commitment|"
    r"verify_merkle|verify_merkle_proof|verify_membership|verify_storage_proof|"
    r"verify_proof|validate_proof|check_proof|consume_proof|authenticate"
    r")\s*\((?P<args>[^;{}]{0,2800})\)"
)

_LET_ASSIGN_RE = re.compile(
    r"(?is)\blet\s+(?:mut\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*(?::[^=;]+)?=\s*(?P<expr>[^;]{0,2600});"
)

_EXTEND_CALL_RE = re.compile(
    r"(?is)\b(?P<buf>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*"
    r"(?:extend_from_slice|extend)\s*\((?P<arg>[^;{}]{0,1600})\)"
)

_PUSH_CALL_RE = re.compile(
    r"(?is)\b(?P<buf>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*"
    r"push\s*\((?P<arg>[^;{}]{0,1200})\)"
)

_UPDATE_CALL_RE = re.compile(
    r"(?is)(?:\b[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?update"
    r"\s*\((?P<arg>[^;{}]{0,1600})\)"
)

_PAYOUT_OR_DISPATCH_EFFECT_RE = re.compile(
    r"(?is)("
    r"(?:transfer|safe_transfer|mint|release|payout|dispatch|deliver|send|"
    r"send_to|enqueue|call)\s*\([^;{}]{0,900}"
    r"(?:to_?address|recipient|receiver|beneficiary|destination_?address|"
    r"dst_?address|target_?address)"
    r"|"
    r"(?:processed|consumed|used|finalized|dispatched|paid|released)"
    r"[A-Za-z0-9_\.]*\s*\.\s*(?:insert|set|save|put|update|push)\s*\("
    r"[^;{}]{0,900}(?:message_?id|msg_?id|transfer_?id|packet_?id|"
    r"request_?id|claim_?id|nonce|sequence)"
    r"|"
    r"(?:accepted|verified|known|stored|commitments?)"
    r"[A-Za-z0-9_\.]*\s*\.\s*(?:insert|set|save|put|update|push)\s*\("
    r"[^;{}]{0,900}(?:source_?commitment|source_?root|remote_?commitment)"
    r")"
)

_SAFE_HELPER_RE = re.compile(
    r"(?i)\b("
    r"BRIDGE_TO_ADDRESS_DOMAIN_FIRE38|TO_ADDRESS_DOMAIN|PAYOUT_DOMAIN|"
    r"DISPATCH_DOMAIN|PROOF_DOMAIN|DOMAIN_SEPARATOR|domain_separator|"
    r"domain_separated|domain_bound|domain_bound_bridge_payout|"
    r"domain_bound_dispatch_digest|bind_domain|bind_payout_domain|"
    r"bind_dispatch_domain|bind_destination_domain|bind_lane_domain|"
    r"bind_channel_domain|scope_proof_domain|scoped_proof_digest|"
    r"validate_domain_binding|ensure_domain_binding|verify_domain_binding|"
    r"ensure_to_address_bound|ensure_destination_chain|ensure_destination_domain|"
    r"ensure_lane_binding|ensure_channel_binding|ensure_source_commitment|"
    r"ensure_message_id_binding|WrongDomain|InvalidDomain|WrongDestination|"
    r"InvalidDestination|WrongLane|InvalidLane|WrongChannel|InvalidChannel|"
    r"WrongRecipient|InvalidRecipient|WrongMessageId|InvalidMessageId"
    r")\b"
)

_DOMAIN_FIELDS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "to_address",
        re.compile(
            r"(?i)\b("
            r"to_?address|recipient|receiver|beneficiary|payout_?to|"
            r"payee|destination_?address|dest_?address|dst_?address|"
            r"target_?address|account_?to"
            r")\b"
        ),
    ),
    (
        "destination_chain",
        re.compile(
            r"(?i)\b("
            r"destination_?chain(?:_?id)?|dest_?chain(?:_?id)?|"
            r"dst_?chain(?:_?id)?|target_?chain(?:_?id)?|"
            r"to_?chain(?:_?id)?|local_?chain(?:_?id)?|"
            r"destination_?domain(?:_?id)?|dest_?domain(?:_?id)?|"
            r"dst_?domain(?:_?id)?|target_?domain(?:_?id)?|"
            r"local_?domain(?:_?id)?|destination_?network(?:_?id)?"
            r")\b"
        ),
    ),
    (
        "source_chain",
        re.compile(
            r"(?i)\b("
            r"source_?chain(?:_?id)?|src_?chain(?:_?id)?|"
            r"origin_?chain(?:_?id)?|remote_?chain(?:_?id)?|"
            r"from_?chain(?:_?id)?|source_?domain(?:_?id)?|"
            r"src_?domain(?:_?id)?|origin_?domain(?:_?id)?|"
            r"remote_?domain(?:_?id)?"
            r")\b"
        ),
    ),
    (
        "lane_channel",
        re.compile(
            r"(?i)\b("
            r"lane_?id|lane|channel_?id|channel|route_?id|route|"
            r"port_?id|path_?id|bridge_?lane|message_?lane|packet_?lane|"
            r"counterparty_?channel|application_?channel"
            r")\b"
        ),
    ),
    (
        "source_commitment",
        re.compile(
            r"(?i)\b("
            r"source_?commitment|source_?root|source_?message_?root|"
            r"source_?payload_?root|origin_?commitment|remote_?commitment|"
            r"origin_?root|remote_?root|source_?receipt_?root"
            r")\b"
        ),
    ),
    (
        "message_id",
        re.compile(
            r"(?i)\b("
            r"message_?id|msg_?id|transfer_?id|packet_?id|request_?id|"
            r"claim_?id|withdrawal_?id|receipt_?id|nonce|sequence|seq_?no"
            r")\b"
        ),
    ),
)

_LOAD_BEARING_FIELDS = {
    "to_address",
    "destination_chain",
    "source_chain",
    "lane_channel",
    "source_commitment",
    "message_id",
}

_COMPARE_RE = re.compile(
    r"(?is)("
    r"ensure(?:_eq)?!\s*\([^;{}]{0,700}\)"
    r"|if\s+[^{};]{0,700}(?:==|!=)[^{};]{0,700}"
    r"|[A-Za-z0-9_\.]+\s*(?:==|!=)\s*[A-Za-z0-9_\.]+"
    r")"
)

_PROOF_CONTEXT_RE = re.compile(
    r"(?i)\b("
    r"proof|decoded_?proof|parsed_?proof|commitment|source_?commitment|"
    r"message_?commitment|payload_?commitment|receipt|packet|leaf|"
    r"claim|withdrawal|transfer"
    r")\b"
)


def _blank(match: re.Match[str]) -> str:
    return "".join("\n" if char == "\n" else " " for char in match.group(0))


def _strip_strings(text: str) -> str:
    return _STRING_RE.sub(_blank, text)


def _signature_text(fn, body, source: bytes) -> str:
    return source[fn.start_byte:body.start_byte].decode("utf-8", errors="replace")


def _domain_groups(text: str) -> set[str]:
    clean = _strip_strings(text)
    return {name for name, pattern in _DOMAIN_FIELDS if pattern.search(clean)}


def _assignments(body: str) -> dict[str, str]:
    return {
        match.group("name"): match.group("expr")
        for match in _LET_ASSIGN_RE.finditer(body)
    }


def _buffer_writes(body: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for match in _EXTEND_CALL_RE.finditer(body):
        out.setdefault(match.group("buf"), []).append(match.group("arg"))
    for match in _PUSH_CALL_RE.finditer(body):
        out.setdefault(match.group("buf"), []).append(match.group("arg"))
    return out


def _expand_expr(
    expr: str,
    assignments: dict[str, str],
    buffers: dict[str, list[str]],
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
            for name, writes in buffers.items():
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
    buffers = _buffer_writes(body)
    inputs: list[str] = []

    for match in _UPDATE_CALL_RE.finditer(body):
        inputs.extend(_expand_expr(match.group("arg"), assignments, buffers))
    for match in _DIRECT_HASH_CALL_RE.finditer(body):
        arg = match.group("arg") or match.group("assoc_arg") or ""
        inputs.extend(_expand_expr(arg, assignments, buffers))
    for expr in assignments.values():
        if _HASH_BUILD_RE.search(expr) or _VERIFY_RE.search(expr):
            inputs.extend(_expand_expr(expr, assignments, buffers))

    return "\n".join(inputs)


def _comparison_bound_fields(body: str) -> set[str]:
    bound: set[str] = set()
    for match in _COMPARE_RE.finditer(body):
        expr = match.group(0)
        if not _PROOF_CONTEXT_RE.search(expr):
            continue
        bound.update(_domain_groups(expr))
    return bound


def _is_bridge_payout_candidate(name: str, signature: str, body: str) -> bool:
    context = f"{name}\n{signature}\n{body}"
    if not (_ENTRY_FN_RE.search(name) or _BRIDGE_CONTEXT_RE.search(context)):
        return False
    if not _BRIDGE_CONTEXT_RE.search(context):
        return False
    if not _PROOF_MATERIAL_RE.search(body):
        return False
    if not (_HASH_BUILD_RE.search(body) or _VERIFY_RE.search(body)):
        return False
    if not _VERIFY_RE.search(body):
        return False
    if not _PAYOUT_OR_DISPATCH_EFFECT_RE.search(body):
        return False
    if _SAFE_HELPER_RE.search(body):
        return False
    return True


def _missing_domain_fields(signature: str, body: str) -> set[str]:
    visible = _domain_groups(f"{signature}\n{body}")
    visible &= _LOAD_BEARING_FIELDS
    if not visible:
        return set()

    auth_inputs = _authenticated_input_text(body)
    if not auth_inputs.strip():
        return set()
    if not _PROOF_MATERIAL_RE.search(auth_inputs):
        return set()

    bound = _domain_groups(auth_inputs)
    bound.update(_comparison_bound_fields(body))
    missing = visible - bound
    if not missing:
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
        if not _is_bridge_payout_candidate(name, signature, body):
            continue

        missing = _missing_domain_fields(signature, body)
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
                    f"pub fn `{name}` verifies bridge proof material then "
                    "uses request-controlled payout or dispatch fields while "
                    "the authenticated proof digest omits "
                    f"{', '.join(sorted(missing))}. Bind to-address, "
                    "destination chain, lane/channel, source commitment, "
                    "and consumed message id into the verified proof digest "
                    f"before payout or dispatch. Class: {ATTACK_CLASS}."
                ),
            }
        )

    return hits

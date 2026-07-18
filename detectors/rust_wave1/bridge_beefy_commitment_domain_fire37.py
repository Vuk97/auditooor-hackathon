"""
bridge_beefy_commitment_domain_fire37.py

Rust detector lift for bridge and BEEFY commitment verification paths.

Fire37 targets public bridge, light-client, BEEFY, MMR, or validator-set
entrypoints that verify payload, MMR leaf, validator set, commitment, or
proof-digest material and then accept a root, commitment, validator set, or
processed proof while visible source chain, destination chain, route, pallet,
network, or client namespace fields remain outside the authenticated bytes.

Source refs:
- reports/detector_lift_fire36_20260605/post_priorities_rust.md
- reference/patterns.dsl/bridge-proof-domain-bypass-umbrella.yaml
- detectors/rust_wave1/bridge_lightclient_route_binding_fire36.py
- detectors/wave17/bridge_beefy_validator_domain_fire35.py

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


DETECTOR_ID = "rust_wave1.bridge_beefy_commitment_domain_fire37"
ATTACK_CLASS = "bridge-proof-domain-bypass"
VERIFICATION_TIER = "tier-3-synthetic-taxonomy-anchored"

_STRING_RE = re.compile(r"(?s)b?r#*\".*?\"#*|b?'(?:\\.|[^'\\])+'")

_BEEFY_CONTEXT_RE = re.compile(
    r"(?i)\b("
    r"bridge|cross[_-]?chain|gateway|portal|router|route|channel|lane|"
    r"light[_-]?client|client[_-]?state|consensus[_-]?state|finality|"
    r"validator[_-]?set|authority[_-]?set|vset|beefy|grandpa|mmr|"
    r"parachain|para[_-]?id|ismp|ibc|pallet|runtime|verifier|"
    r"verification|proof|storage[_-]?proof|state[_-]?root|commitment|"
    r"payload|digest|header|packet|namespace"
    r")\b"
)

_ENTRY_FN_RE = re.compile(
    r"(?i)("
    r"(submit|update|import|accept|verify|validate|process|finalize|"
    r"relay|prove|consume|store|record)"
    r".*(beefy|mmr|validator|authority|commitment|digest|proof|root|"
    r"payload|leaf|header|client|route|pallet|packet)"
    r"|"
    r"(beefy|mmr|validator|authority|commitment|digest|proof|root|"
    r"payload|leaf|header|client|route|pallet|packet)"
    r".*(submit|update|import|accept|verify|validate|process|finalize|"
    r"relay|prove|consume|store|record)"
    r")"
)

_COMMITMENT_MATERIAL_RE = re.compile(
    r"(?i)\b("
    r"payload[_-]?hash|payload|message[_-]?hash|message[_-]?commitment|"
    r"commitment[_-]?(?:hash|root|digest)?|signed[_-]?commitment|"
    r"mmr[_-]?(?:root|leaf|leaf[_-]?hash|proof)?|leaf[_-]?hash|leaf|"
    r"validator[_-]?set[_-]?(?:id|root|hash|digest|length|len)?|"
    r"authority[_-]?set[_-]?(?:id|root|hash|length|len)?|"
    r"vset[_-]?(?:id|root|hash|length|len)?|proof[_-]?(?:digest|hash|root)?|"
    r"storage[_-]?proof|state[_-]?root|header[_-]?hash|header|"
    r"bitfield|bit[_-]?field[_-]?hash|signature|sig"
    r")\b"
)

_HASH_BUILD_RE = re.compile(
    r"(?is)\b(?:"
    r"(?:[A-Za-z_][A-Za-z0-9_:]*::)?"
    r"(?:keccak256|sha256|sha3|blake2_?256|blake2b|blake2s|blake3|"
    r"twox_?256|poseidon|hash|hash_bytes|digest|digest_bytes|"
    r"proof_digest|commitment_hash|leaf_hash|payload_hash|"
    r"signed_commitment|transcript_hash)"
    r")\s*\("
    r"|[A-Za-z0-9_]+::digest\s*\("
    r"|\.finalize\s*\("
)

_DIRECT_HASH_CALL_RE = re.compile(
    r"(?is)\b(?:"
    r"(?:[A-Za-z_][A-Za-z0-9_:]*::)?"
    r"(?:keccak256|sha256|sha3|blake2_?256|blake2b|blake2s|blake3|"
    r"twox_?256|poseidon|hash|hash_bytes|digest|digest_bytes|"
    r"proof_digest|commitment_hash|leaf_hash|payload_hash|"
    r"signed_commitment|transcript_hash)"
    r")\s*\((?P<arg>[^;{}]{0,2200})\)"
    r"|[A-Za-z0-9_]+::digest\s*\((?P<assoc_arg>[^;{}]{0,2200})\)"
)

_VERIFY_RE = re.compile(
    r"(?is)\b(?:[A-Za-z0-9_]+(?:::|\.)\s*)?("
    r"verify_beefy_commitment|verify_beefy_digest|verify_signed_commitment|"
    r"verify_commitment|verify_commitment_hash|verify_payload|"
    r"verify_payload_digest|verify_validator_set|verify_validator_set_hash|"
    r"verify_validator_set_proof|verify_authority_set|verify_finality|"
    r"verify_mmr_leaf|verify_mmr_leaf_proof|verify_mmr_root|"
    r"verify_leaf|verify_leaf_proof|verify_proof_digest|verify_digest|"
    r"verify_light_client_proof|verify_client_update|verify_state_root|"
    r"verify_storage_root|verify_header|verify_membership|"
    r"verify_storage_proof|verify_proof|verify_merkle|verify_merkle_proof|"
    r"check_membership|check_proof|validate_proof|validate_header|"
    r"consume_proof|mmr_verify|merkle_verify|authenticate"
    r")\s*\((?P<args>[^;{}]{0,2400})\)"
)

_LET_ASSIGN_RE = re.compile(
    r"(?is)\blet\s+(?:mut\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*(?::[^=;]+)?=\s*(?P<expr>[^;]{0,2600});"
)

_EXTEND_CALL_RE = re.compile(
    r"(?is)\b(?P<buf>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*"
    r"(?:extend_from_slice|extend)\s*\((?P<arg>[^;{}]{0,1400})\)"
)

_PUSH_CALL_RE = re.compile(
    r"(?is)\b(?P<buf>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*"
    r"push\s*\((?P<arg>[^;{}]{0,900})\)"
)

_UPDATE_CALL_RE = re.compile(
    r"(?is)(?:\b[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?update"
    r"\s*\((?P<arg>[^;{}]{0,1400})\)"
)

_ACCEPTANCE_EFFECT_RE = re.compile(
    r"(?is)\b(?:self\.)?[A-Za-z_][A-Za-z0-9_\.]*"
    r"(?:accepted|trusted|verified|known|processed|consumed|finalized|"
    r"imported|stored|root|roots|commitment|commitments|mmr|leaf|leaves|"
    r"payload|payloads|validator_set|validator_sets|authority_set|"
    r"client_state|consensus_state|client_roots|routes)"
    r"[A-Za-z0-9_\.]*\s*\.\s*(?:insert|set|save|put|update|push)\s*\("
    r"|self\s*\.\s*(?:latest|current|trusted|accepted|verified)"
    r"[A-Za-z0-9_\.]*(?:root|commitment|validator|authority|client|"
    r"state|route|digest|leaf)[A-Za-z0-9_\.]*\s*="
)

_SAFE_HELPER_RE = re.compile(
    r"(?i)\b("
    r"BEEFY_COMMITMENT_DOMAIN_FIRE37|BEEFY_COMMITMENT_DOMAIN|"
    r"BEEFY_PAYLOAD_DOMAIN|BEEFY_MMR_LEAF_DOMAIN|BEEFY_PROOF_DOMAIN|"
    r"BEEFY_TRANSCRIPT_DOMAIN|DOMAIN_SEPARATOR|domain_separator|"
    r"domain_separated|domain_bound|domain_bound_beefy_commitment|"
    r"domain_bound_commitment_digest|domain_bound_payload_digest|"
    r"bind_domain|bind_beefy_domain|bind_beefy_commitment_domain|"
    r"bind_mmr_leaf_domain|bind_payload_domain|bind_proof_domain|"
    r"bind_route_domain|bind_client_domain|bind_pallet_domain|"
    r"scope_proof_domain|scoped_proof_digest|scoped_commitment_digest|"
    r"validate_domain_binding|ensure_domain_binding|verify_domain_binding|"
    r"ensure_source_chain|ensure_destination_chain|ensure_route_binding|"
    r"ensure_client_namespace|ensure_pallet|WrongDomain|InvalidDomain|"
    r"WrongChain|InvalidChain|WrongSource|InvalidSource|WrongDestination|"
    r"InvalidDestination|WrongRoute|InvalidRoute|WrongPallet|InvalidPallet|"
    r"WrongNetwork|InvalidNetwork|WrongClient|InvalidClient|"
    r"WrongNamespace|InvalidNamespace"
    r")\b"
)

_DOMAIN_FIELDS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "source_chain",
        re.compile(
            r"(?i)\b("
            r"source_?chain(?:_?id)?|src_?chain(?:_?id)?|"
            r"origin_?chain(?:_?id)?|remote_?chain(?:_?id)?|"
            r"from_?chain(?:_?id)?|relay_?chain(?:_?id)?|"
            r"source_?domain(?:_?id)?|src_?domain(?:_?id)?|"
            r"origin_?domain(?:_?id)?|remote_?domain(?:_?id)?|"
            r"source_?network(?:_?id)?|"
            r"source_?para(?:_?id)?|src_?para(?:_?id)?|"
            r"origin_?para(?:_?id)?|source_?parachain(?:_?id)?"
            r")\b"
        ),
    ),
    (
        "destination_chain",
        re.compile(
            r"(?i)\b("
            r"destination_?chain(?:_?id)?|dest_?chain(?:_?id)?|"
            r"dst_?chain(?:_?id)?|target_?chain(?:_?id)?|"
            r"local_?chain(?:_?id)?|to_?chain(?:_?id)?|"
            r"destination_?domain(?:_?id)?|dest_?domain(?:_?id)?|"
            r"dst_?domain(?:_?id)?|target_?domain(?:_?id)?|"
            r"local_?domain(?:_?id)?|destination_?network(?:_?id)?|"
            r"local_?network(?:_?id)?|destination_?para(?:_?id)?|local_?para(?:_?id)?|"
            r"destination_?parachain(?:_?id)?|block\s*\.\s*chainid|chainid"
            r")\b"
        ),
    ),
    (
        "route",
        re.compile(
            r"(?i)\b("
            r"route_?id|route|channel_?id|channel|lane_?id|lane|"
            r"port_?id|path_?id|bridge_?lane|message_?lane|packet_?lane|"
            r"counterparty_?channel|application_?channel"
            r")\b"
        ),
    ),
    (
        "pallet",
        re.compile(
            r"(?i)\b("
            r"pallet_?id|pallet_?index|pallet_?instance|pallet_?prefix|"
            r"module_?id|module_?prefix|runtime_?module|runtime_?pallet|"
            r"storage_?prefix|storage_?module"
            r")\b"
        ),
    ),
    (
        "network",
        re.compile(
            r"(?i)\b("
            r"network_?id|network|genesis_?hash|fork_?id|fork_?hash|"
            r"relay_?parent|relay_?parent_?number|relay_?parent_?hash|"
            r"spec_?version|protocol_?version"
            r")\b"
        ),
    ),
    (
        "client_namespace",
        re.compile(
            r"(?i)\b("
            r"client_?id|light_?client_?id|beefy_?client_?id|"
            r"consensus_?client_?id|ibc_?client_?id|ismp_?client_?id|"
            r"client_?namespace|verifier_?namespace|verifier_?domain|"
            r"verifier_?id|namespace|domain_?separator|domain_?id|"
            r"domain_?tag|gateway_?id|bridge_?id|bridge_?account|"
            r"verifying_?contract"
            r")\b"
        ),
    ),
)

_LOAD_BEARING_FIELDS = {
    "source_chain",
    "destination_chain",
    "route",
    "pallet",
    "network",
    "client_namespace",
}

_COMPARE_RE = re.compile(
    r"(?is)("
    r"ensure(?:_eq)?!\s*\([^;{}]{0,600}\)"
    r"|if\s+[^{};]{0,600}(?:==|!=)[^{};]{0,600}"
    r"|[A-Za-z0-9_\.]+\s*(?:==|!=)\s*[A-Za-z0-9_\.]+"
    r")"
)

_COMMITMENT_CONTEXT_RE = re.compile(
    r"(?i)\b("
    r"decoded_?commitment|parsed_?commitment|commitment_?key|proof_?key|"
    r"payload_?key|mmr_?leaf|mmr_?root|validator_?set|authority_?set|"
    r"proof_?digest|commitment_?digest|signed_?commitment"
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

    while changed and len(parts) < 120:
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
    for match in _VERIFY_RE.finditer(body):
        inputs.extend(_expand_expr(match.group("args"), assignments, buffers))
    for expr in assignments.values():
        if _HASH_BUILD_RE.search(expr) or _VERIFY_RE.search(expr):
            inputs.extend(_expand_expr(expr, assignments, buffers))

    return "\n".join(inputs)


def _comparison_bound_fields(body: str) -> set[str]:
    bound: set[str] = set()
    for match in _COMPARE_RE.finditer(body):
        expr = match.group(0)
        if not _COMMITMENT_CONTEXT_RE.search(expr):
            continue
        bound.update(_domain_groups(expr))
    return bound


def _is_beefy_commitment_candidate(name: str, signature: str, body: str) -> bool:
    context = f"{name}\n{signature}\n{body}"
    if not (_ENTRY_FN_RE.search(name) or _BEEFY_CONTEXT_RE.search(context)):
        return False
    if not _BEEFY_CONTEXT_RE.search(context):
        return False
    if not _COMMITMENT_MATERIAL_RE.search(body):
        return False
    if not (_HASH_BUILD_RE.search(body) or _VERIFY_RE.search(body)):
        return False
    if not _VERIFY_RE.search(body):
        return False
    if not _ACCEPTANCE_EFFECT_RE.search(body):
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
    if not _COMMITMENT_MATERIAL_RE.search(auth_inputs):
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
        if not _is_beefy_commitment_candidate(name, signature, body):
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
                    f"pub fn `{name}` verifies BEEFY or bridge commitment "
                    "material while the authenticated digest omits "
                    f"{', '.join(sorted(missing))}. Bind source chain, "
                    "destination chain, route, pallet, network, and client "
                    "namespace into the payload, MMR leaf, validator-set, "
                    "or proof digest before accepting roots or commitments. "
                    f"Class: {ATTACK_CLASS}."
                ),
            }
        )

    return hits

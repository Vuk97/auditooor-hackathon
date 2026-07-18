"""
bridge_lightclient_domain_fire35.py

Rust detector lift for bridge-proof-domain-bypass in light-client proof
verification paths.

Fire35 targets public bridge or light-client entrypoints that accept a
state root, message commitment, validator-set digest, or proof digest after
hashing or verifying proof material while visible chain, client, pallet,
gateway, channel, or nonce-lane fields remain outside the authenticated
bytes. It requires a persistent acceptance effect before reporting so pure
helper digest routines stay silent.

Source refs:
- reports/detector_lift_fire34_20260605/post_priorities_rust.md
- reference/patterns.dsl/bridge-proof-domain-bypass-umbrella.yaml
- reference/patterns.dsl/bridge-proof-domain-bypass-verifier-digest-omits-domain.yaml
- detectors/rust_wave1/rust_bridge_replay_domain_fire33.py
- detectors/rust_wave1/signature_transcript_domain_fire34.py

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


DETECTOR_ID = "rust_wave1.bridge_lightclient_domain_fire35"
ATTACK_CLASS = "bridge-proof-domain-bypass"
VERIFICATION_TIER = "tier-3-synthetic-taxonomy-anchored"

_STRING_RE = re.compile(r"(?s)b?r#*\".*?\"#*|b?'(?:\\.|[^'\\])+'")

_LIGHTCLIENT_CONTEXT_RE = re.compile(
    r"(?i)\b("
    r"bridge|cross[_-]?chain|gateway|portal|router|channel|lane|"
    r"light[_-]?client|client[_-]?state|consensus[_-]?state|finality|"
    r"ismp|ibc|pallet|runtime|verifier|verification|proof|merkle|mmr|"
    r"state[_-]?root|message[_-]?commitment|commitment|validator[_-]?set|"
    r"proof[_-]?digest|header|packet"
    r")\b"
)

_ENTRY_FN_RE = re.compile(
    r"(?i)("
    r"(submit|update|import|accept|verify|validate|process|finalize|relay|"
    r"prove|consume|store|record)"
    r".*(light|client|bridge|proof|root|commitment|validator|header|packet)"
    r"|"
    r"(light|client|bridge|proof|root|commitment|validator|header|packet)"
    r".*(submit|update|import|accept|verify|validate|process|finalize|relay|"
    r"prove|consume|store|record)"
    r")"
)

_PROOF_MATERIAL_RE = re.compile(
    r"(?i)\b("
    r"state[_-]?root|storage[_-]?root|header[_-]?root|receipt[_-]?root|"
    r"proof[_-]?root|root|message[_-]?commitment|commitment[_-]?hash|"
    r"commitment|validator[_-]?set[_-]?(?:hash|root|digest)?|vset[_-]?hash|"
    r"proof[_-]?digest|proof[_-]?hash|proof|digest|leaf|leaf[_-]?hash|"
    r"header|packet|payload[_-]?hash|message[_-]?hash|mmr|merkle"
    r")\b"
)

_HASH_BUILD_RE = re.compile(
    r"(?is)\b("
    r"keccak256|sha256|sha3|blake2b|blake2s|blake3|poseidon|"
    r"hash|hash_bytes|digest|digest_bytes|proof_digest|commitment_hash"
    r")\s*\("
    r"|[A-Za-z0-9_]+::digest\s*\("
    r"|\.finalize\s*\("
)

_DIRECT_HASH_CALL_RE = re.compile(
    r"(?is)\b(?:keccak256|sha256|sha3|blake2b|blake2s|blake3|poseidon|"
    r"hash|hash_bytes|digest|digest_bytes|proof_digest|commitment_hash)"
    r"\s*\((?P<arg>[^;{}]{0,1800})\)"
    r"|[A-Za-z0-9_]+::digest\s*\((?P<assoc_arg>[^;{}]{0,1800})\)"
)

_VERIFY_RE = re.compile(
    r"(?is)\b(?:[A-Za-z0-9_]+(?:::|\.)\s*)?("
    r"verify_light_client_proof|verify_client_update|verify_consensus_state|"
    r"verify_state_root|verify_root|verify_storage_root|verify_header|"
    r"verify_commitment|verify_message_commitment|verify_validator_set|"
    r"verify_validator_set_hash|verify_finality|verify_proof|verify_merkle|"
    r"verify_merkle_proof|check_membership|check_proof|validate_proof|"
    r"validate_header|consume_proof|mmr_verify|merkle_verify|authenticate"
    r")\s*\((?P<args>[^;{}]{0,1800})\)"
)

_LET_ASSIGN_RE = re.compile(
    r"(?is)\blet\s+(?:mut\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*(?::[^=;]+)?=\s*(?P<expr>[^;]{0,2400});"
)

_EXTEND_CALL_RE = re.compile(
    r"(?is)\b(?P<buf>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*"
    r"(?:extend_from_slice|extend)\s*\((?P<arg>[^;{}]{0,1200})\)"
)

_PUSH_CALL_RE = re.compile(
    r"(?is)\b(?P<buf>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*"
    r"push\s*\((?P<arg>[^;{}]{0,800})\)"
)

_UPDATE_CALL_RE = re.compile(
    r"(?is)(?:\b[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?update"
    r"\s*\((?P<arg>[^;{}]{0,1200})\)"
)

_ACCEPTANCE_EFFECT_RE = re.compile(
    r"(?is)\b(?:self\.)?[A-Za-z_][A-Za-z0-9_\.]*"
    r"(?:accepted|trusted|verified|known|processed|consumed|finalized|"
    r"imported|stored|root|roots|commitment|commitments|validator_set|"
    r"validator_sets|client_state|consensus_state)[A-Za-z0-9_\.]*"
    r"\s*\.\s*(?:insert|set|save|put|update|push)\s*\("
    r"|self\s*\.\s*(?:latest|current|trusted|accepted|verified)"
    r"[A-Za-z0-9_\.]*(?:root|commitment|validator|client|state)"
    r"[A-Za-z0-9_\.]*\s*="
)

_SAFE_HELPER_RE = re.compile(
    r"(?i)\b("
    r"domain_separated|domain_bound|bind_domain|bind_light_client_domain|"
    r"bind_client_domain|bind_proof_domain|scope_proof_domain|"
    r"scoped_proof_digest|scoped_commitment_digest|domain_bound_digest|"
    r"verify_domain|ensure_domain|WrongDomain|InvalidDomain|WrongClient|"
    r"InvalidClient|WrongChannel|InvalidChannel|WrongGateway|InvalidGateway"
    r")\b"
)

_DOMAIN_FIELDS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "chain_id",
        re.compile(
            r"(?i)\b("
            r"chain_?id|chainid|network_?id|genesis_?hash|fork_?id|"
            r"source_?chain|src_?chain|origin_?chain|remote_?chain|"
            r"destination_?chain|dest_?chain|dst_?chain|target_?chain|"
            r"local_?chain|para_?id|parachain_?id"
            r")\b"
        ),
    ),
    (
        "client_id",
        re.compile(
            r"(?i)\b("
            r"client_?id|light_?client_?id|consensus_?client_?id|"
            r"ibc_?client_?id|ismp_?client_?id|ref_?client_?id|"
            r"client_?type|client_?state_?id"
            r")\b"
        ),
    ),
    (
        "pallet_id",
        re.compile(
            r"(?i)\b("
            r"pallet_?id|pallet_?index|pallet_?instance|module_?id|"
            r"runtime_?module|runtime_?pallet|module_?prefix|"
            r"pallet_?prefix"
            r")\b"
        ),
    ),
    (
        "gateway",
        re.compile(
            r"(?i)\b("
            r"gateway|gateway_?id|bridge_?id|bridge_?address|portal_?id|"
            r"verifying_?contract|verifier_?domain|verifier_?id|"
            r"bridge_?account|consumer_?address"
            r")\b"
        ),
    ),
    (
        "channel",
        re.compile(
            r"(?i)\b("
            r"channel|channel_?id|lane|lane_?id|route|route_?id|"
            r"port_?id|path_?id|counterparty_?channel"
            r")\b"
        ),
    ),
    (
        "nonce_lane",
        re.compile(
            r"(?i)\b("
            r"nonce_?lane|lane_?nonce|sequence_?lane|lane_?sequence|"
            r"replay_?lane|inbound_?nonce_?lane|outbound_?nonce_?lane|"
            r"message_?lane|packet_?lane"
            r")\b"
        ),
    ),
    (
        "domain_separator",
        re.compile(
            r"(?i)\b("
            r"domain_?separator|domain_?id|domain_?tag|domain_?hash|"
            r"namespace|scope_?id|protocol_?version|version_?tag"
            r")\b"
        ),
    ),
)

_LOAD_BEARING_FIELDS = {
    "chain_id",
    "client_id",
    "pallet_id",
    "gateway",
    "channel",
    "nonce_lane",
}


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

    while changed and len(parts) < 100:
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

    for match in _EXTEND_CALL_RE.finditer(body):
        inputs.extend(_expand_expr(match.group("arg"), assignments, buffers))
    for match in _PUSH_CALL_RE.finditer(body):
        inputs.extend(_expand_expr(match.group("arg"), assignments, buffers))
    for match in _UPDATE_CALL_RE.finditer(body):
        inputs.extend(_expand_expr(match.group("arg"), assignments, buffers))
    for match in _DIRECT_HASH_CALL_RE.finditer(body):
        arg = match.group("arg") or match.group("assoc_arg") or ""
        inputs.extend(_expand_expr(arg, assignments, buffers))
    for match in _VERIFY_RE.finditer(body):
        inputs.extend(_expand_expr(match.group("args"), assignments, buffers))
    for expr in assignments.values():
        if _HASH_BUILD_RE.search(expr):
            inputs.extend(_expand_expr(expr, assignments, buffers))

    return "\n".join(inputs)


def _is_lightclient_acceptance_candidate(name: str, signature: str, body: str) -> bool:
    context = f"{name}\n{signature}\n{body}"
    if not (_ENTRY_FN_RE.search(name) or _LIGHTCLIENT_CONTEXT_RE.search(context)):
        return False
    if not _PROOF_MATERIAL_RE.search(body):
        return False
    if not (_HASH_BUILD_RE.search(body) or _VERIFY_RE.search(body)):
        return False
    if not _ACCEPTANCE_EFFECT_RE.search(body):
        return False
    if _SAFE_HELPER_RE.search(body):
        return False
    return True


def _missing_domain_fields(signature: str, body: str) -> set[str]:
    visible = _domain_groups(f"{signature}\n{body}")
    if not (visible & _LOAD_BEARING_FIELDS):
        return set()

    auth_inputs = _authenticated_input_text(body)
    if not auth_inputs.strip():
        return set()
    if not _PROOF_MATERIAL_RE.search(auth_inputs):
        return set()

    bound = _domain_groups(auth_inputs)
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
        if not _is_lightclient_acceptance_candidate(name, signature, body):
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
                    f"pub fn `{name}` accepts light-client proof material "
                    "after hashing or verifying authenticated bytes that omit "
                    f"{', '.join(sorted(missing))}. Bind chain id, client id, "
                    "pallet id, gateway, channel, and nonce-lane context into "
                    f"the proof digest before storing roots, commitments, or "
                    f"validator sets. Class: {ATTACK_CLASS}."
                ),
            }
        )

    return hits

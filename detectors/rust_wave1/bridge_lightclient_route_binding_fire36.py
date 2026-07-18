"""
bridge_lightclient_route_binding_fire36.py

Rust detector lift for bridge-proof-domain-bypass in light-client and
validator-set verification routes.

Fire36 targets verification entrypoints that expose route/domain coordinates
such as chain id, client id, route id, pallet id, or verifier namespace, then
decode or verify proof-key material while those coordinates remain outside the
signed commitment, proof key, or explicit key-to-route equality checks. It
requires an acceptance write so helper-only digest builders stay silent.

Source refs:
- reports/detector_lift_fire35_20260605/post_priorities_rust.md
- reference/patterns.dsl/bridge-proof-domain-bypass-umbrella.yaml
- reference/patterns.dsl/bridge-proof-domain-bypass-verifier-digest-omits-domain.yaml
- detectors/rust_wave1/bridge_lightclient_domain_fire35.py
- detectors/rust_wave1/rust_bridge_replay_domain_fire33.py

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


DETECTOR_ID = "rust_wave1.bridge_lightclient_route_binding_fire36"
ATTACK_CLASS = "bridge-proof-domain-bypass"
VERIFICATION_TIER = "tier-3-synthetic-taxonomy-anchored"

_STRING_RE = re.compile(r"(?s)b?r#*\".*?\"#*|b?'(?:\\.|[^'\\])+'")

_LIGHTCLIENT_CONTEXT_RE = re.compile(
    r"(?i)\b("
    r"bridge|cross[_-]?chain|gateway|portal|router|route|channel|lane|"
    r"light[_-]?client|client[_-]?state|consensus[_-]?state|finality|"
    r"validator[_-]?set|vset|beefy|grandpa|ismp|ibc|pallet|runtime|"
    r"verifier|verification|proof|storage[_-]?proof|state[_-]?root|"
    r"commitment|header|packet|namespace"
    r")\b"
)

_ENTRY_FN_RE = re.compile(
    r"(?i)("
    r"(submit|update|import|accept|verify|validate|process|finalize|"
    r"relay|prove|consume|store|record)"
    r".*(route|client|light|proof|root|commitment|validator|header|key)"
    r"|"
    r"(route|client|light|proof|root|commitment|validator|header|key)"
    r".*(submit|update|import|accept|verify|validate|process|finalize|"
    r"relay|prove|consume|store|record)"
    r")"
)

_PROOF_KEY_MATERIAL_RE = re.compile(
    r"(?i)\b("
    r"proof_?key|proof\.key|proof\.path|storage_?key|state_?key|"
    r"trie_?key|key_?bytes|proof_?path|storage_?path|decoded_?key|"
    r"parsed_?key|key_?parts|commitment_?key|membership_?key"
    r")\b"
)

_PROOF_KEY_DECODE_RE = re.compile(
    r"(?is)\b("
    r"(?:ProofKey|StorageKey|StateKey|TrieKey|ProofPath|RouteKey)"
    r"\s*::\s*(?:decode|try_from|from_bytes|parse)\s*\("
    r"|"
    r"(?:decode|parse|read|extract)_[A-Za-z0-9_]*(?:proof|storage|state|"
    r"route|membership)?_?key\s*\("
    r"|"
    r"try_from\s*\([^;{}]*(?:proof\s*\.\s*key|proof_key|storage_key|"
    r"key_bytes|proof_path)"
    r")"
)

_PROOF_MATERIAL_RE = re.compile(
    r"(?i)\b("
    r"state[_-]?root|storage[_-]?root|header[_-]?root|receipt[_-]?root|"
    r"message[_-]?commitment|commitment[_-]?hash|validator[_-]?set[_-]?"
    r"(?:hash|root|digest)?|vset[_-]?hash|proof[_-]?digest|proof[_-]?hash|"
    r"proof|digest|leaf|leaf[_-]?hash|header|packet|payload[_-]?hash|"
    r"message[_-]?hash|mmr|merkle|nodes"
    r")\b"
)

_HASH_BUILD_RE = re.compile(
    r"(?is)\b("
    r"keccak256|sha256|sha3|blake2b|blake2s|blake3|poseidon|"
    r"hash|hash_bytes|digest|digest_bytes|proof_digest|commitment_hash|"
    r"signed_commitment|transcript_hash"
    r")\s*\("
    r"|[A-Za-z0-9_]+::digest\s*\("
    r"|\.finalize\s*\("
)

_DIRECT_HASH_CALL_RE = re.compile(
    r"(?is)\b(?:keccak256|sha256|sha3|blake2b|blake2s|blake3|poseidon|"
    r"hash|hash_bytes|digest|digest_bytes|proof_digest|commitment_hash|"
    r"signed_commitment|transcript_hash)"
    r"\s*\((?P<arg>[^;{}]{0,1800})\)"
    r"|[A-Za-z0-9_]+::digest\s*\((?P<assoc_arg>[^;{}]{0,1800})\)"
)

_VERIFY_RE = re.compile(
    r"(?is)\b(?:[A-Za-z0-9_]+(?:::|\.)\s*)?("
    r"verify_light_client_proof|verify_client_update|verify_consensus_state|"
    r"verify_state_root|verify_root|verify_storage_root|verify_header|"
    r"verify_commitment|verify_message_commitment|verify_validator_set|"
    r"verify_validator_set_hash|verify_finality|verify_membership|"
    r"verify_storage_proof|verify_proof|verify_merkle|verify_merkle_proof|"
    r"check_membership|check_proof|validate_proof|validate_header|"
    r"consume_proof|mmr_verify|merkle_verify|authenticate"
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
    r"validator_sets|client_state|consensus_state|client_roots|routes)"
    r"[A-Za-z0-9_\.]*\s*\.\s*(?:insert|set|save|put|update|push)\s*\("
    r"|self\s*\.\s*(?:latest|current|trusted|accepted|verified)"
    r"[A-Za-z0-9_\.]*(?:root|commitment|validator|client|state|route)"
    r"[A-Za-z0-9_\.]*\s*="
)

_SAFE_HELPER_RE = re.compile(
    r"(?i)\b("
    r"domain_separated|domain_bound|bind_domain|bind_light_client_domain|"
    r"bind_client_domain|bind_proof_domain|bind_route_domain|"
    r"bind_route_key|scope_proof_domain|route_bound_key|"
    r"validate_route_binding|ensure_route_binding|verify_route_binding|"
    r"proof_key_matches_route|key_matches_route|WrongDomain|InvalidDomain|"
    r"WrongClient|InvalidClient|WrongRoute|InvalidRoute|WrongChain|"
    r"InvalidChain|WrongPallet|InvalidPallet|WrongNamespace|"
    r"InvalidNamespace"
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
        "route_id",
        re.compile(
            r"(?i)\b("
            r"route_?id|route|channel_?id|channel|lane_?id|lane|"
            r"port_?id|path_?id|counterparty_?channel"
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
        "verifier_namespace",
        re.compile(
            r"(?i)\b("
            r"verifier_?namespace|verifier_?domain|verifier_?id|"
            r"namespace|domain_?separator|domain_?id|domain_?tag|"
            r"gateway_?id|bridge_?id|gateway|bridge_?account|"
            r"verifying_?contract"
            r")\b"
        ),
    ),
)

_LOAD_BEARING_FIELDS = {
    "chain_id",
    "client_id",
    "route_id",
    "pallet_id",
    "verifier_namespace",
}

_COMPARE_RE = re.compile(
    r"(?is)("
    r"ensure(?:_eq)?!\s*\([^;{}]{0,500}\)"
    r"|if\s+[^{};]{0,500}(?:==|!=)[^{};]{0,500}"
    r"|[A-Za-z0-9_\.]+\s*(?:==|!=)\s*[A-Za-z0-9_\.]+"
    r")"
)

_DECODED_KEY_CONTEXT_RE = re.compile(
    r"(?i)\b("
    r"decoded_?key|proof_?key|storage_?key|state_?key|route_?key|"
    r"parsed_?key|key_?parts|membership_?key|commitment_?key"
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
        if _HASH_BUILD_RE.search(expr) or _VERIFY_RE.search(expr):
            inputs.extend(_expand_expr(expr, assignments, buffers))

    return "\n".join(inputs)


def _decoded_key_comparison_fields(body: str) -> set[str]:
    bound: set[str] = set()
    for match in _COMPARE_RE.finditer(body):
        expr = match.group(0)
        if not _DECODED_KEY_CONTEXT_RE.search(expr):
            continue
        bound.update(_domain_groups(expr))
    return bound


def _is_route_binding_candidate(name: str, signature: str, body: str) -> bool:
    context = f"{name}\n{signature}\n{body}"
    if not (_ENTRY_FN_RE.search(name) or _LIGHTCLIENT_CONTEXT_RE.search(context)):
        return False
    if not (_PROOF_KEY_DECODE_RE.search(body) or _PROOF_KEY_MATERIAL_RE.search(body)):
        return False
    if not _PROOF_MATERIAL_RE.search(body):
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


def _missing_route_fields(signature: str, body: str) -> set[str]:
    visible = _domain_groups(f"{signature}\n{body}")
    visible &= _LOAD_BEARING_FIELDS
    if not visible:
        return set()

    auth_inputs = _authenticated_input_text(body)
    if not auth_inputs.strip():
        return set()
    if not (_PROOF_KEY_MATERIAL_RE.search(auth_inputs) or _PROOF_MATERIAL_RE.search(auth_inputs)):
        return set()

    bound = _domain_groups(auth_inputs)
    bound.update(_decoded_key_comparison_fields(body))
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
        if not _is_route_binding_candidate(name, signature, body):
            continue

        missing = _missing_route_fields(signature, body)
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
                    f"pub fn `{name}` accepts light-client route proof "
                    "material while the decoded proof key or signed "
                    f"commitment omits {', '.join(sorted(missing))}. Bind "
                    "chain id, client id, route id, pallet id, and verifier "
                    "namespace into the proof key or commitment before "
                    f"storing accepted roots or validator sets. Class: "
                    f"{ATTACK_CLASS}."
                ),
            }
        )

    return hits

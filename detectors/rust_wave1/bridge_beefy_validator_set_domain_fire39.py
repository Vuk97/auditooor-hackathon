"""
bridge_beefy_validator_set_domain_fire39.py

Rust detector lift for BEEFY bridge validator-set update paths where a
verified commitment, MMR, or finality proof is accepted while active or next
validator-set identity fields remain outside the authenticated transcript.

Seed refs:
- reports/detector_lift_fire38_20260605/post_priorities_rust.md
- detectors/rust_wave1/bridge_to_address_domain_fire38.py
- detectors/rust_wave1/bridge_beefy_commitment_domain_fire37.py
- bridge-beefy-commitment-domain-fire37-positive
- oversized-toaddress-in-sendfrom-breaks-layerzero-channel-positive

verification_tier: tier-3-synthetic-taxonomy-anchored
attack_class: bridge-proof-domain-bypass
context_pack_id: auditooor.vault_context_pack.v1:resume:cbdd9eeb5255863c
context_pack_hash: cbdd9eeb5255863c4870d83e88642e9c4a3eef8e7cdfb8b5fb9a8ee7ac5a25d8
MCP receipt: .auditooor/memory_context_receipt.json
NOT_SUBMIT_READY
R40/R76/R80 caveat: detector hits are source-review candidates only, not proof.
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


DETECTOR_ID = "rust_wave1.bridge_beefy_validator_set_domain_fire39"
ATTACK_CLASS = "bridge-proof-domain-bypass"
VERIFICATION_TIER = "tier-3-synthetic-taxonomy-anchored"

_STRING_RE = re.compile(r"(?s)b?r#*\".*?\"#*|b?'(?:\\.|[^'\\])+'")

_BEEFY_VALIDATOR_CONTEXT_RE = re.compile(
    r"(?i)\b("
    r"bridge|cross[_-]?chain|gateway|portal|light[_-]?client|client[_-]?state|"
    r"consensus[_-]?state|finality|beefy|mmr|grandpa|authority[_-]?set|"
    r"validator[_-]?set|vset|validator|authority|commitment|payload|"
    r"proof|digest|header|root|verifier|verification"
    r")\b"
)

_ENTRY_FN_RE = re.compile(
    r"(?i)("
    r"(submit|update|import|accept|verify|validate|process|finalize|relay|"
    r"prove|consume|store|record)"
    r".*(beefy|mmr|validator|authority|finality|commitment|proof|digest|root)"
    r"|"
    r"(beefy|mmr|validator|authority|finality|commitment|proof|digest|root)"
    r".*(submit|update|import|accept|verify|validate|process|finalize|relay|"
    r"prove|consume|store|record)"
    r")"
)

_VALIDATOR_PROOF_MATERIAL_RE = re.compile(
    r"(?i)\b("
    r"signed[_-]?commitment|commitment[_-]?(?:hash|root|digest)?|"
    r"payload[_-]?hash|payload|mmr[_-]?(?:root|leaf|leaf[_-]?hash|proof)?|"
    r"validator[_-]?set[_-]?(?:id|root|hash|digest|length|len)?|"
    r"authority[_-]?set[_-]?(?:id|root|hash|length|len)?|"
    r"vset[_-]?(?:id|root|hash|length|len)?|proof[_-]?(?:digest|hash|root)?|"
    r"finality[_-]?proof|header[_-]?hash|header|bitfield|bit[_-]?field|"
    r"signature|signatures|sig"
    r")\b"
)

_HASH_BUILD_RE = re.compile(
    r"(?is)\b(?:"
    r"(?:[A-Za-z_][A-Za-z0-9_:]*::)?"
    r"(?:keccak256|sha256|sha3|blake2_?256|blake2b|blake2s|blake3|"
    r"twox_?256|poseidon|hash|hash_bytes|digest|digest_bytes|"
    r"proof_digest|commitment_hash|payload_hash|signed_commitment|"
    r"validator_set_hash|authority_set_hash|transcript_hash)"
    r")\s*\("
    r"|[A-Za-z0-9_]+::digest\s*\("
    r"|\.finalize\s*\("
)

_DIRECT_HASH_CALL_RE = re.compile(
    r"(?is)\b(?:"
    r"(?:[A-Za-z_][A-Za-z0-9_:]*::)?"
    r"(?:keccak256|sha256|sha3|blake2_?256|blake2b|blake2s|blake3|"
    r"twox_?256|poseidon|hash|hash_bytes|digest|digest_bytes|"
    r"proof_digest|commitment_hash|payload_hash|signed_commitment|"
    r"validator_set_hash|authority_set_hash|transcript_hash)"
    r")\s*\((?P<arg>[^;{}]{0,2600})\)"
    r"|[A-Za-z0-9_]+::digest\s*\((?P<assoc_arg>[^;{}]{0,2600})\)"
)

_VERIFY_RE = re.compile(
    r"(?is)\b(?:[A-Za-z0-9_]+(?:::|\.)\s*)?("
    r"verify_beefy_validator_set|verify_validator_set_update|"
    r"verify_validator_set_proof|verify_validator_set_hash|"
    r"verify_next_validator_set|verify_authority_set|"
    r"verify_authority_set_update|verify_next_authority_set|"
    r"verify_beefy_commitment|verify_beefy_digest|"
    r"verify_signed_commitment|verify_commitment|verify_payload|"
    r"verify_finality|verify_mmr_leaf|verify_mmr_leaf_proof|"
    r"verify_mmr_root|verify_proof_digest|verify_digest|"
    r"verify_light_client_proof|verify_client_update|verify_header|"
    r"verify_membership|verify_proof|check_proof|validate_proof|"
    r"consume_proof|mmr_verify|merkle_verify|authenticate"
    r")\s*\((?P<args>[^;{}]{0,3000})\)"
)

_LET_ASSIGN_RE = re.compile(
    r"(?is)\blet\s+(?:mut\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*(?::[^=;]+)?=\s*(?P<expr>[^;]{0,3000});"
)

_EXTEND_CALL_RE = re.compile(
    r"(?is)\b(?P<buf>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*"
    r"(?:extend_from_slice|extend)\s*\((?P<arg>[^;{}]{0,1800})\)"
)

_PUSH_CALL_RE = re.compile(
    r"(?is)\b(?P<buf>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*"
    r"push\s*\((?P<arg>[^;{}]{0,1200})\)"
)

_UPDATE_CALL_RE = re.compile(
    r"(?is)(?:\b[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?update"
    r"\s*\((?P<arg>[^;{}]{0,1800})\)"
)

_ACCEPTANCE_EFFECT_RE = re.compile(
    r"(?is)\b(?:self\.)?[A-Za-z_][A-Za-z0-9_\.]*"
    r"(?:accepted|trusted|verified|known|processed|consumed|finalized|"
    r"imported|stored|root|roots|commitment|commitments|mmr|payload|"
    r"validator_set|validator_sets|authority_set|authority_sets|"
    r"client_state|consensus_state|validator_set_lengths)"
    r"[A-Za-z0-9_\.]*\s*\.\s*(?:insert|set|save|put|update|push)\s*\("
    r"|self\s*\.\s*(?:latest|current|trusted|accepted|verified|active|next)"
    r"[A-Za-z0-9_\.]*(?:root|commitment|validator|authority|set|client|"
    r"state|digest|leaf|id)[A-Za-z0-9_\.]*\s*="
)

_SAFE_HELPER_RE = re.compile(
    r"(?i)\b("
    r"BEEFY_VALIDATOR_SET_DOMAIN_FIRE39|BEEFY_VALIDATOR_SET_DOMAIN|"
    r"BEEFY_AUTHORITY_SET_DOMAIN|BEEFY_VALIDATOR_DOMAIN|"
    r"BEEFY_TRANSCRIPT_DOMAIN|BEEFY_PROOF_DOMAIN|DOMAIN_SEPARATOR|"
    r"domain_separator|domain_separated|domain_bound|"
    r"domain_bound_beefy_validator_set|domain_bound_validator_set_digest|"
    r"domain_bound_authority_set_digest|bind_domain|bind_beefy_domain|"
    r"bind_validator_set_domain|bind_authority_set_domain|"
    r"bind_current_validator_set|bind_next_validator_set|"
    r"bind_client_domain|scope_proof_domain|scoped_proof_digest|"
    r"validate_domain_binding|ensure_domain_binding|verify_domain_binding|"
    r"validate_validator_set_domain|ensure_validator_set_binding|"
    r"proof_matches_validator_set|validator_set_matches_proof|"
    r"reload_current_validator_set|load_current_validator_set|"
    r"checkpoint_validator_set|checkpoint_authority_set|"
    r"consume_validator_set_update_once|consume_once|mark_proof_consumed|"
    r"WrongDomain|InvalidDomain|WrongValidatorSet|InvalidValidatorSet|"
    r"WrongAuthoritySet|InvalidAuthoritySet|WrongClient|InvalidClient"
    r")\b"
)

_DOMAIN_FIELDS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "current_validator_set_id",
        re.compile(
            r"(?i)\b("
            r"current_?validator_?set_?id|active_?validator_?set_?id|"
            r"current_?authority_?set_?id|active_?authority_?set_?id|"
            r"current_?set_?id|active_?set_?id|"
            r"current_?set\s*\.\s*id|active_?set\s*\.\s*id|"
            r"current_?validator_?set\s*\.\s*id|"
            r"current_?authority_?set\s*\.\s*id"
            r")\b"
        ),
    ),
    (
        "next_validator_set_id",
        re.compile(
            r"(?i)\b("
            r"next_?validator_?set_?id|new_?validator_?set_?id|"
            r"pending_?validator_?set_?id|next_?authority_?set_?id|"
            r"new_?authority_?set_?id|pending_?authority_?set_?id|"
            r"next_?set_?id|new_?set_?id|pending_?set_?id|"
            r"next_?set\s*\.\s*id|new_?set\s*\.\s*id|"
            r"pending_?set\s*\.\s*id|next_?validator_?set\s*\.\s*id|"
            r"next_?authority_?set\s*\.\s*id|"
            r"proof\s*\.\s*next_?validator_?set_?id|"
            r"proof\s*\.\s*next_?authority_?set_?id"
            r")\b"
        ),
    ),
    (
        "current_validator_set_root",
        re.compile(
            r"(?i)\b("
            r"current_?validator_?set_?root|active_?validator_?set_?root|"
            r"current_?authority_?set_?root|active_?authority_?set_?root|"
            r"current_?set_?root|active_?set_?root|"
            r"current_?set\s*\.\s*root|active_?set\s*\.\s*root|"
            r"current_?validator_?set\s*\.\s*root|"
            r"current_?authority_?set\s*\.\s*root"
            r")\b"
        ),
    ),
    (
        "next_validator_set_root",
        re.compile(
            r"(?i)\b("
            r"next_?validator_?set_?root|new_?validator_?set_?root|"
            r"pending_?validator_?set_?root|next_?authority_?set_?root|"
            r"new_?authority_?set_?root|pending_?authority_?set_?root|"
            r"next_?set_?root|new_?set_?root|pending_?set_?root|"
            r"next_?set\s*\.\s*root|new_?set\s*\.\s*root|"
            r"pending_?set\s*\.\s*root|next_?validator_?set\s*\.\s*root|"
            r"next_?authority_?set\s*\.\s*root|"
            r"proof\s*\.\s*next_?validator_?set_?root|"
            r"proof\s*\.\s*next_?authority_?set_?root|"
            r"proof\s*\.\s*validator_?set_?root|"
            r"proof\s*\.\s*authority_?set_?root"
            r")\b"
        ),
    ),
    (
        "validator_set_length",
        re.compile(
            r"(?i)\b("
            r"validator_?set_?(?:len|length)|authority_?set_?(?:len|length)|"
            r"validator_?count|authority_?count|current_?set\s*\.\s*len|"
            r"next_?set\s*\.\s*len|new_?set\s*\.\s*len|"
            r"current_?validator_?set\s*\.\s*len|"
            r"next_?validator_?set\s*\.\s*len|"
            r"current_?authority_?set\s*\.\s*len|"
            r"next_?authority_?set\s*\.\s*len|"
            r"proof\s*\.\s*(?:validator_?set_?(?:len|length)|validator_?count)"
            r")\b"
        ),
    ),
    (
        "source_chain",
        re.compile(
            r"(?i)\b("
            r"source_?chain(?:_?id)?|src_?chain(?:_?id)?|"
            r"origin_?chain(?:_?id)?|remote_?chain(?:_?id)?|"
            r"source_?domain(?:_?id)?|src_?domain(?:_?id)?|"
            r"origin_?domain(?:_?id)?|remote_?domain(?:_?id)?|"
            r"source_?network(?:_?id)?|source_?para(?:_?id)?"
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
            r"local_?network(?:_?id)?|block\s*\.\s*chainid|chainid"
            r")\b"
        ),
    ),
    (
        "client_namespace",
        re.compile(
            r"(?i)\b("
            r"client_?id|light_?client_?id|beefy_?client_?id|"
            r"consensus_?client_?id|client_?namespace|verifier_?namespace|"
            r"verifier_?domain|verifier_?id|namespace|gateway_?id|"
            r"bridge_?id|verifying_?contract"
            r")\b"
        ),
    ),
)

_LOAD_BEARING_FIELDS = {
    "current_validator_set_id",
    "next_validator_set_id",
    "current_validator_set_root",
    "next_validator_set_root",
    "validator_set_length",
    "source_chain",
    "destination_chain",
    "client_namespace",
}

_CORE_FIELDS = {
    "current_validator_set_id",
    "next_validator_set_id",
    "current_validator_set_root",
    "next_validator_set_root",
    "validator_set_length",
}

_COMPARE_RE = re.compile(
    r"(?is)("
    r"ensure(?:_eq)?!\s*\([^;{}]{0,900}\)"
    r"|if\s+[^{};]{0,900}(?:==|!=)[^{};]{0,900}"
    r"|[A-Za-z0-9_\.]+\s*(?:==|!=)\s*[A-Za-z0-9_\.]+"
    r")"
)

_VALIDATOR_CONTEXT_RE = re.compile(
    r"(?i)\b("
    r"proof|commitment|validator_?set|authority_?set|vset|current_?set|"
    r"next_?set|active_?set|pending_?set|validator|authority"
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

    while changed and len(parts) < 160:
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
        if not _VALIDATOR_CONTEXT_RE.search(expr):
            continue
        bound.update(_domain_groups(expr))
    return bound


def _is_beefy_validator_set_candidate(name: str, signature: str, body: str) -> bool:
    context = f"{name}\n{signature}\n{body}"
    if not (_ENTRY_FN_RE.search(name) or _BEEFY_VALIDATOR_CONTEXT_RE.search(context)):
        return False
    if not _BEEFY_VALIDATOR_CONTEXT_RE.search(context):
        return False
    if not _VALIDATOR_PROOF_MATERIAL_RE.search(body):
        return False
    if not (_HASH_BUILD_RE.search(body) or _VERIFY_RE.search(body)):
        return False
    if not _VERIFY_RE.search(body):
        return False
    if not _ACCEPTANCE_EFFECT_RE.search(body):
        return False
    if _SAFE_HELPER_RE.search(body):
        return False
    visible = _domain_groups(context) & _LOAD_BEARING_FIELDS
    return bool(visible & _CORE_FIELDS)


def _missing_domain_fields(signature: str, body: str) -> set[str]:
    visible = _domain_groups(f"{signature}\n{body}")
    visible &= _LOAD_BEARING_FIELDS
    if not (visible & _CORE_FIELDS):
        return set()

    auth_inputs = _authenticated_input_text(body)
    if not auth_inputs.strip():
        return set()
    if not _VALIDATOR_PROOF_MATERIAL_RE.search(auth_inputs):
        return set()

    bound = _domain_groups(auth_inputs)
    bound.update(_comparison_bound_fields(body))
    missing = visible - bound
    if not (missing & _CORE_FIELDS):
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
        if not _is_beefy_validator_set_candidate(name, signature, body):
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
                    f"pub fn `{name}` verifies BEEFY validator-set proof "
                    "material while the authenticated transcript omits "
                    f"{', '.join(sorted(missing))}. Bind the current and "
                    "next validator-set id/root/length plus bridge chain or "
                    "client namespace fields into the proof digest, or guard "
                    "them against proof-carried values before accepting the "
                    f"validator set. Class: {ATTACK_CLASS}. NOT_SUBMIT_READY."
                ),
            }
        )

    return hits

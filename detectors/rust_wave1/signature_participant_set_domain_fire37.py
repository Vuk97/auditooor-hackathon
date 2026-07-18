"""
signature_participant_set_domain_fire37.py

Rust detector lift for signature-replay-cross-domain on threshold-signature
and participant-set verification paths.

Fire37 targets public FROST, BLS, sr25519, ed25519, or secp256k1 style
verification entrypoints that authenticate payload bytes while visible
participant-set, signer-role, threshold, session, chain, or purpose-domain
fields remain outside the signed bytes. It requires a verified signature plus
a state effect, so helper-only verification functions are intentionally
ignored.

Source refs:
- reports/detector_lift_fire36_20260605/post_priorities_rust.md
- reference/patterns.dsl/signature-replay-missing-domain.yaml
- detectors/rust_wave1/signature_domain_replay_fire36.py
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


DETECTOR_ID = "rust_wave1.signature_participant_set_domain_fire37"
ATTACK_CLASS = "signature-replay-cross-domain"
VERIFICATION_TIER = "tier-3-synthetic-taxonomy-anchored"

_STRING_RE = re.compile(r"(?s)b?r#*\".*?\"#*|b?'(?:\\.|[^'\\])+'")

_PARTICIPANT_CONTEXT_RE = re.compile(
    r"(?i)\b("
    r"frost|bls|threshold|aggregate|committee|validator|participant|"
    r"participant_?set|signer_?set|signer_?role|signature_?share|"
    r"sig_?share|share_?verify|group_?key|public_?key_?package|"
    r"round_?id|signing_?session|session_?id|sr25519|ed25519|"
    r"secp256k1|schnorr|ecdsa|verify|signature|transcript|digest"
    r")\b"
)

_ENTRY_FN_RE = re.compile(
    r"(?i)("
    r"(verify|validate|execute|consume|claim|redeem|release|settle|permit|"
    r"authorize|submit|process|complete).*"
    r"(signature|signed|share|participant|committee|validator|threshold|"
    r"session|frost|bls|ed25519|sr25519|secp|schnorr|digest|transcript)"
    r"|"
    r"(signature|signed|share|participant|committee|validator|threshold|"
    r"session|frost|bls|ed25519|sr25519|secp|schnorr|digest|transcript).*"
    r"(verify|validate|execute|consume|claim|redeem|release|settle|permit|"
    r"authorize|submit|process|complete)"
    r")"
)

_AUTH_BUILD_RE = re.compile(
    r"(?is)\b("
    r"Transcript::new|merlin::Transcript|SigningTranscript|SigningContext|"
    r"signing_context|signing_transcript|new_transcript|build_transcript|"
    r"transcript_bytes|challenge_bytes|challenge_scalar|challenge|"
    r"compute_challenge|keccak256|sha256|sha3|blake2b|blake2s|blake3|"
    r"poseidon|hash|hash_bytes|digest|digest_bytes|to_signing_bytes|"
    r"signing_bytes|sign_bytes|message_bytes"
    r")\b"
    r"|[A-Za-z0-9_]+::digest\s*\("
    r"|Message::from_digest\s*\("
    r"|\.finalize\s*\("
)

_DIRECT_HASH_CALL_RE = re.compile(
    r"(?is)\b(?:keccak256|sha256|sha3|blake2b|blake2s|blake3|poseidon|"
    r"hash|hash_bytes|digest|digest_bytes|to_signing_bytes|signing_bytes|"
    r"sign_bytes|message_bytes)\s*\((?P<arg>[^;{}]{0,2000})\)"
    r"|[A-Za-z0-9_]+::digest\s*\((?P<assoc_arg>[^;{}]{0,2000})\)"
    r"|Message::from_digest\s*\((?P<message_arg>[^;{}]{0,1200})\)"
)

_LET_ASSIGN_RE = re.compile(
    r"(?is)\blet\s+(?:mut\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*(?::[^=;]+)?=\s*(?P<expr>[^;]{0,2600});"
)

_AUTH_WRITE_RE = re.compile(
    r"(?is)\b(?P<buf>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*"
    r"(?P<method>"
    r"append_message|append_u64|append_i64|append_bytes|append_public_key|"
    r"append_commitment|append_scalar|append_point|append_participant|"
    r"commit_bytes|commit_point|commit_scalar|commit_public_key|"
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
    r"verify_transcript|verify_message|verify_batch|verify_share|"
    r"verify_signature_share|verify_sig_share|verify_commitment_share|"
    r"aggregate_verify|fast_aggregate_verify|verify_aggregate|"
    r"ed25519_verify|sr25519_verify|ecdsa_verify|secp256k1_verify|"
    r"secp256r1_verify|schnorr_verify|bls_verify|frost_verify|"
    r"recover_signature|recover|is_valid_signature|authenticate_signature|"
    r"verify"
    r")\s*\((?P<args>[^;{}]{0,2400})\)"
)

_PAYLOAD_MATERIAL_RE = re.compile(
    r"(?i)\b("
    r"message|msg|payload|payload_hash|call|calldata|recipient|receiver|"
    r"amount|value|asset|asset_id|token|params|order|withdrawal|transfer|"
    r"claim|permit|intent|request|operation|instruction|data|sign_bytes|"
    r"signing_bytes|transcript_bytes"
    r")\b"
)

_STATE_EFFECT_RE = re.compile(
    r"(?is)"
    r"\b(?:transfer|safe_transfer|mint|burn|withdraw|release|claim|redeem|"
    r"settle|credit|debit|execute|dispatch|approve|fulfill|finalize|"
    r"complete|pay_out|rotate|slash|reward)\s*\("
    r"|\.insert\s*\("
    r"|\.save\s*\("
    r"|\.set\s*\("
    r"|\.remove\s*\("
    r"|\[[^\]]+\]\s*=\s*(?:true|1)"
)

_SAFE_HELPER_RE = re.compile(
    r"(?i)\b("
    r"domain_separated|domain_bound|domain_bound_digest|"
    r"domain_bound_transcript|bind_domain|bind_chain|bind_session|"
    r"bind_purpose|bind_participant|bind_participant_set|bind_signer_role|"
    r"bind_threshold|bind_signature_domain|bind_signature_scope|"
    r"scoped_signature_digest|scoped_transcript|replay_bound_transcript|"
    r"verify_with_domain|verify_with_scope|verify_with_participant_set|"
    r"verify_with_committee|ensure_domain|ensure_chain|ensure_session|"
    r"ensure_participant_set|ensure_signer_role|ensure_threshold"
    r")\s*\("
)

_SCOPE_FIELDS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "participant_set",
        re.compile(
            r"(?i)\b("
            r"participant_?set|participant_?set_?hash|participant_?bitmap|"
            r"participant_?root|signer_?set|signer_?set_?hash|"
            r"signer_?bitmap|validator_?set|validator_?set_?hash|"
            r"committee|committee_?hash|committee_?root|roster|member_?set|"
            r"member_?root|threshold_?set|group_?public_?key|group_?key|"
            r"public_?key_?package|verification_?key_?set"
            r")\b"
        ),
    ),
    (
        "signer_role",
        re.compile(
            r"(?i)\b("
            r"signer_?role|role_?id|authority_?role|validator_?role|"
            r"participant_?role|sender_?role|receiver_?role|aggregator|"
            r"coordinator|proposer|executor_?role|approver_?role"
            r")\b"
        ),
    ),
    (
        "threshold",
        re.compile(
            r"(?i)\b("
            r"threshold|required_?signers|required_?shares|required_?votes|"
            r"min_?signers|min_?shares|quorum|quorum_?size|"
            r"participant_?count|signer_?count|committee_?size"
            r")\b"
        ),
    ),
    (
        "session_id",
        re.compile(
            r"(?i)\b("
            r"session_?id|signing_?session|signing_?round|round_?id|"
            r"epoch|view|slot|checkpoint_?id|ceremony_?id|transcript_?id|"
            r"auth_?session"
            r")\b"
        ),
    ),
    (
        "chain_id",
        re.compile(
            r"(?i)\b("
            r"chain_?id|chainid|network_?id|fork_?id|genesis_?hash|"
            r"source_?chain|src_?chain|destination_?chain|dest_?chain|"
            r"dst_?chain|runtime_?chain|para_?id|parachain_?id"
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
)

_PARTICIPANT_FIELDS = {"participant_set", "signer_role", "threshold"}
_LOAD_BEARING_FIELDS = {
    "participant_set",
    "signer_role",
    "threshold",
    "session_id",
    "chain_id",
    "purpose_domain",
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


def _is_participant_domain_candidate(name: str, signature: str, body: str) -> bool:
    context = f"{name}\n{signature}\n{body}"
    if not (_ENTRY_FN_RE.search(name) or _PARTICIPANT_CONTEXT_RE.search(context)):
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
    if not (visible & _PARTICIPANT_FIELDS):
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
        if not _is_participant_domain_candidate(name, signature, body):
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
                    f"pub fn `{name}` verifies signature payload bytes "
                    "that omit participant-set domain binding for "
                    f"{', '.join(sorted(missing))}. Bind participant set, "
                    "signer role, threshold, session id, chain id, and "
                    "purpose domain into the signed transcript before "
                    f"applying state effects. Class: {ATTACK_CLASS}."
                ),
            }
        )

    return hits

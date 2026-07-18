"""
signature_transcript_domain_fire34.py

Rust detector lift for signature-replay-cross-domain transcript omissions.

Fire34 targets public verification paths that construct sign-bytes,
transcripts, permit digests, or authorization digests from message material
while visible replay-domain fields remain outside the signed transcript. It
requires signature verification plus a replayable state effect before
reporting, so plain helper verification functions are intentionally ignored.

Source refs:
- reports/detector_lift_fire33_20260605/post_priorities_rust.md
- reference/patterns.dsl/signature-replay-missing-domain.yaml
- detectors/rust_wave1/rust_bridge_replay_domain_fire33.py
- detectors/wave17/bridge_digest_domain_fire33.py

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


DETECTOR_ID = "rust_wave1.signature_transcript_domain_fire34"
ATTACK_CLASS = "signature-replay-cross-domain"
VERIFICATION_TIER = "tier-3-synthetic-taxonomy-anchored"

_STRING_RE = re.compile(r"(?s)b?r#*\".*?\"#*|b?'(?:\\.|[^'\\])+'")

_SIGNED_CONTEXT_RE = re.compile(
    r"(?i)\b("
    r"signature|signed|signer|verify|verification|recover|ed25519|ecdsa|"
    r"secp256|schnorr|permit|authorization|authorize|auth|transcript|"
    r"sign_?bytes|typed_?data|eip712|digest|replay|intent"
    r")\b"
)

_ENTRY_FN_RE = re.compile(
    r"(?i)("
    r"(verify|validate|execute|consume|claim|redeem|release|settle|permit|"
    r"authorize|submit|process).*"
    r"(signature|signed|permit|authorization|intent|digest|transcript|claim)"
    r"|"
    r"(signature|signed|permit|authorization|intent|digest|transcript|claim).*"
    r"(verify|validate|execute|consume|claim|redeem|release|settle|permit|"
    r"authorize|submit|process)"
    r")"
)

_HASH_BUILD_RE = re.compile(
    r"(?is)\b("
    r"keccak256|sha256|sha3|blake2b|blake2s|blake3|poseidon|"
    r"hash|hash_bytes|digest|digest_bytes"
    r")\s*\("
    r"|[A-Za-z0-9_]+::digest\s*\("
    r"|Message::from_digest\s*\("
    r"|\.finalize\s*\("
)

_DIRECT_HASH_CALL_RE = re.compile(
    r"(?is)\b(?:keccak256|sha256|sha3|blake2b|blake2s|blake3|poseidon|"
    r"hash|hash_bytes|digest|digest_bytes)\s*\((?P<arg>[^;{}]{0,1600})\)"
    r"|[A-Za-z0-9_]+::digest\s*\((?P<assoc_arg>[^;{}]{0,1600})\)"
    r"|Message::from_digest\s*\((?P<message_arg>[^;{}]{0,1200})\)"
)

_LET_ASSIGN_RE = re.compile(
    r"(?is)\blet\s+(?:mut\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*(?::[^=;]+)?=\s*(?P<expr>[^;]{0,2200});"
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

_VERIFY_RE = re.compile(
    r"(?is)\b("
    r"verify_signature|verify_sig|verify_permit|verify_authorization|"
    r"verify_intent|verify_digest|authenticate_signature|ed25519_verify|"
    r"ecdsa_verify|secp256k1_verify|secp256r1_verify|schnorr_verify|"
    r"recover_signature|recover|is_valid_signature|SignatureChecker"
    r")\s*\("
)

_MESSAGE_MATERIAL_RE = re.compile(
    r"(?i)\b("
    r"message|msg|payload|payload_hash|call|calldata|recipient|receiver|"
    r"amount|value|asset|asset_id|token|token_id|params|order|quote|"
    r"withdrawal|transfer|claim|permit|intent|deadline|expiry|data"
    r")\b"
)

_STATE_EFFECT_RE = re.compile(
    r"(?is)"
    r"\b(?:transfer|safe_transfer|mint|burn|withdraw|release|claim|redeem|"
    r"settle|credit|debit|execute|dispatch|approve|set_allowance|"
    r"fulfill|finalize)\s*\("
    r"|\.insert\s*\("
    r"|\.save\s*\("
    r"|\.set\s*\("
    r"|\.remove\s*\("
    r"|\[[^\]]+\]\s*=\s*(?:true|1)"
)

_SAFE_HELPER_RE = re.compile(
    r"(?i)\b("
    r"domain_separated|domain_bound|bind_domain|bind_signature_domain|"
    r"hash_typed_data|hashTypedData|_hash_typed_data_v4|_hashTypedDataV4|"
    r"domain_bound_digest|domain_bound_transcript|scoped_signature_digest"
    r")\s*\("
)

_DOMAIN_FIELDS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "chain_id",
        re.compile(
            r"(?i)\b(chain_?id|chainid|network_?id|fork_?id|genesis_?hash)\b"
        ),
    ),
    (
        "domain_separator",
        re.compile(
            r"(?i)\b("
            r"domain_separator|domain_?id|domain_?tag|domain_?salt|"
            r"domain_?hash|domain_?bytes|namespace|scope_?id"
            r")\b"
        ),
    ),
    (
        "contract_id",
        re.compile(
            r"(?i)\b("
            r"contract_?id|contract_?address|verifying_?contract|"
            r"address_this|program_?id|module_?id|pallet_?id|"
            r"target_?contract|target_?program|consumer_?address"
            r")\b"
        ),
    ),
    (
        "account",
        re.compile(
            r"(?i)\b("
            r"owner_?account|account_?id|account|wallet_?owner|wallet|"
            r"authority|delegator|user_?id|user_account"
            r")\b"
        ),
    ),
    (
        "nonce",
        re.compile(
            r"(?i)\b("
            r"nonce|sig_?nonce|signature_?nonce|permit_?nonce|"
            r"replay_?nonce|sequence|salt|counter"
            r")\b"
        ),
    ),
    (
        "purpose",
        re.compile(
            r"(?i)\b("
            r"purpose|purpose_?tag|action|method|operation|selector|"
            r"intent_?type|permit_?type|call_?kind|entry_?point"
            r")\b"
        ),
    ),
)

_LOAD_BEARING_FIELDS = {"chain_id", "domain_separator", "contract_id", "nonce", "purpose"}


def _blank(match: re.Match[str]) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in match.group(0))


def _strip_strings(text: str) -> str:
    return _STRING_RE.sub(_blank, text)


def _signature_text(fn, body, source: bytes) -> str:
    return source[fn.start_byte:body.start_byte].decode("utf-8", errors="replace")


def _field_groups(text: str) -> set[str]:
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

    while changed and len(parts) < 80:
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


def _transcript_input_text(body: str) -> str:
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
        arg = (
            match.group("arg")
            or match.group("assoc_arg")
            or match.group("message_arg")
            or ""
        )
        inputs.extend(_expand_expr(arg, assignments, buffers))
    for expr in assignments.values():
        if _HASH_BUILD_RE.search(expr):
            inputs.extend(_expand_expr(expr, assignments, buffers))

    return "\n".join(inputs)


def _is_signature_transcript_candidate(name: str, signature: str, body: str) -> bool:
    context = f"{name}\n{signature}\n{body}"
    if not (_ENTRY_FN_RE.search(name) or _SIGNED_CONTEXT_RE.search(context)):
        return False
    if not (_HASH_BUILD_RE.search(body) and _VERIFY_RE.search(body)):
        return False
    if _SAFE_HELPER_RE.search(body):
        return False
    if not _STATE_EFFECT_RE.search(body):
        return False
    return True


def _missing_domain_fields(signature: str, body: str) -> set[str]:
    visible = _field_groups(f"{signature}\n{body}")
    if len(visible) < 2:
        return set()

    transcript_inputs = _transcript_input_text(body)
    if not (_MESSAGE_MATERIAL_RE.search(transcript_inputs) and transcript_inputs.strip()):
        return set()

    bound = _field_groups(transcript_inputs)
    missing = visible - bound

    if not (missing & _LOAD_BEARING_FIELDS) and len(missing) < 2:
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
        body = body_text_nocomment(body_node, source)
        if not _is_signature_transcript_candidate(name, signature, body):
            continue

        missing = _missing_domain_fields(signature, body)
        if not missing:
            continue

        line, col = line_col(fn)
        hits.append(
            {
                "detector_id": DETECTOR_ID,
                "attack_class": ATTACK_CLASS,
                "severity": "high",
                "line": line,
                "col": col,
                "fn_name": name,
                "snippet": snippet_of(fn, source)[:240],
                "message": (
                    f"pub fn `{name}` verifies a signature over replayable "
                    "transcript material but the signed digest omits "
                    f"{', '.join(sorted(missing))}. Bind chain id, domain "
                    "separator, contract or program id, account, nonce, and "
                    "purpose into the sign-bytes before performing state "
                    f"effects. Class: {ATTACK_CLASS}."
                ),
            }
        )

    return hits

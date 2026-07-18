"""
signature_domain_or_signer_uniqueness_fire20.py

Rust same-class recall lift for signature-replay-cross-domain.

Flags three replay-prone signature shapes:
1. Signed digest material is built without visible domain, contract, chain,
   nonce, action, or entrypoint binding.
2. Multisig validation counts signatures toward a threshold without tracking
   distinct recovered signers.
3. A public action path accepts a signature but skips the vault, account, or
   authority signer validation used by the guarded sibling path.
"""

from __future__ import annotations

import re

from _util import (
    body_text_nocomment,
    fn_body,
    fn_name,
    function_items,
    in_test_cfg,
    line_col,
    snippet_of,
    source_nocomment,
    text_of,
)


DETECTOR_ID = "rust_wave1.signature_domain_or_signer_uniqueness_fire20"
ATTACK_CLASS = "signature-replay-cross-domain"

_STRING_RE = re.compile(r"(?s)b?r#*\".*?\"#*|b?'(?:\\.|[^'\\])+'")

_SIGNED_CONTEXT_RE = re.compile(
    r"(?i)\b("
    r"signature|signed|signer|permit|authorization|typed_?data|eip712|"
    r"user_?op|digest|domain_separator|recover|secp|ed25519|ecdsa|"
    r"multisig|threshold|attestor|validator|vault|authority"
    r")\b"
)

_HASH_RE = re.compile(
    r"(?i)\b(?:keccak256|sha256|blake2b|blake2s|blake3|poseidon|hash)\s*\("
)

_FILE_DOMAIN_CONTEXT_RE = re.compile(
    r"(?i)\b(permit|authorization|user_?op|typed_?data|eip712|domain_separator)\b"
)

_DIRECT_HASH_CALL_RE = re.compile(
    r"(?is)\b(?:keccak256|sha256|blake2b|blake2s|blake3|poseidon|hash)"
    r"\s*\((?P<arg>[^;{}]{0,1200})\)"
)

_UPDATE_OR_EXTEND_RE = re.compile(
    r"(?is)(?:\.update|\.extend_from_slice)\s*\((?P<arg>[^;{}]{0,900})\)"
)

_LET_ASSIGN_RE = re.compile(
    r"(?is)\blet\s+(?:mut\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*(?::[^=;]+)?=\s*(?P<expr>[^;]{0,1600});"
)

_DOMAIN_FIELDS = (
    (
        "chain_id",
        re.compile(r"(?i)\b(chain_?id|chainid|network_id|fork_id)\b"),
    ),
    (
        "contract_or_program",
        re.compile(
            r"(?i)\b("
            r"verifying_contract|contract_address|current_contract|"
            r"program_id|address_this|target_contract|target_consumer"
            r")\b"
        ),
    ),
    (
        "entrypoint_or_action",
        re.compile(r"(?i)\b(entry_?point|action|method|selector|operation)\b"),
    ),
    (
        "nonce_or_deadline",
        re.compile(r"(?i)\b(nonce|salt|deadline|expiry|expires_at)\b"),
    ),
)

_EIP712_FLAT_ARRAY_RE = re.compile(
    r"(?is)"
    r"(?:eip-?712|typed_?data|TYPE_HASH|type_hash).*?"
    r"(?:uint256\s*\[\s*2\s*\]\s*\[\s*\]|ids_and_amounts).*?"
    r"for\s*\([^)]*\)\s*in\s+ids_and_amounts.*?"
    r"extend_from_slice\s*\(\s*&?buf\s*\).*?"
    r"keccak256\s*\(\s*&?flat_encoded\s*\)"
)

_EIP712_RECURSIVE_GUARD_RE = re.compile(
    r"(?is)\b(element_hash|element_hashes|hash_uint256_2_element|"
    r"hash_each|map\s*\(|flat_map\s*\(|collect\s*\(\s*\))\b"
)

_SIG_COLLECTION_RE = re.compile(r"(?i)\b(signatures|sigs|sig_shares)\b")
_THRESHOLD_RE = re.compile(r"(?i)\b(threshold|required_signatures|required)\b")
_COUNT_INC_RE = re.compile(
    r"(?i)\b(valid_count|count|approved|verified)\s*(?:\+=\s*1|=\s*\1\s*\+\s*1)"
)
_AUTH_OR_VERIFY_RE = re.compile(
    r"(?i)\b("
    r"contains\s*\(|verify|recover|attestors|validators|authorized|"
    r"secp|ed25519|ecdsa|pubkey|address|signer"
    r")\b"
)
_UNIQUE_GUARD_RE = re.compile(
    r"(?i)\b("
    r"seen|unique|dedup|distinct|HashSet|BTreeSet|already_counted|"
    r"counted_signers"
    r")\b|\.insert\s*\([^)]*(?:signer|addr|address|pubkey|key)"
)

_SIGNATURE_PARAM_RE = re.compile(r"(?i)\b_?(?:signature|sig)\s*:\s*")
_ROLE_OR_DOMAIN_RE = re.compile(
    r"(?i)\b(vault|account|owner|authority|signer|action|commitment|payload)\b"
)
_ACTION_NAME_RE = re.compile(
    r"(?i)\b("
    r"buyout|execute|withdraw|claim|settle|transfer|release|redeem|accept|"
    r"approve|fulfill|liquidate|cancel"
    r")"
)
_STATEFUL_EFFECT_RE = re.compile(
    r"(?i)(?:\.remove\s*\(|\.insert\s*\(|\.set\s*\(|\.save\s*\(|"
    r"\.transfer\s*\(|invoke_contract|emit_event|burn|mint|execute)"
)
_SIGNATURE_VALIDATION_RE = re.compile(
    r"(?i)\b("
    r"_?validate(?:_[A-Za-z0-9]+)*|verify(?:_[A-Za-z0-9]+)*|"
    r"recover|require(?:_[A-Za-z0-9]+)*|assert(?:_[A-Za-z0-9]+)*|"
    r"check(?:_[A-Za-z0-9]+)*|authenticate|authorize|ed25519_verify|"
    r"secp256|ecdsa"
    r")\b"
)


def _blank(match: re.Match[str]) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in match.group(0))


def _strip_strings(text: str) -> str:
    return _STRING_RE.sub(_blank, text)


def _signature_text(fn, body, source: bytes) -> str:
    return source[fn.start_byte:body.start_byte].decode("utf-8", errors="replace")


def _field_groups(text: str) -> set[str]:
    clean = _strip_strings(text)
    return {name for name, pattern in _DOMAIN_FIELDS if pattern.search(clean)}


def _hash_input_text(body: str) -> str:
    assignments = {
        match.group("name"): match.group("expr")
        for match in _LET_ASSIGN_RE.finditer(body)
    }
    inputs: list[str] = []

    for match in _UPDATE_OR_EXTEND_RE.finditer(body):
        inputs.append(match.group("arg"))
    for match in _DIRECT_HASH_CALL_RE.finditer(body):
        inputs.append(match.group("arg"))

    expanded = list(inputs)
    for expr in inputs:
        for name, assigned in assignments.items():
            if re.search(rf"\b{re.escape(name)}\b", expr):
                expanded.append(assigned)
    return "\n".join(expanded)


def _missing_domain_binding(
    name: str,
    signature: str,
    body: str,
    file_text: str,
) -> set[str]:
    local_context = f"{name}\n{signature}\n{body}"
    context = local_context
    if _FILE_DOMAIN_CONTEXT_RE.search(local_context):
        context = f"{local_context}\n{file_text}"

    if not (_SIGNED_CONTEXT_RE.search(context) and _HASH_RE.search(body)):
        return set()

    visible = _field_groups(context)
    if not visible:
        return set()

    hash_inputs = _hash_input_text(body)
    if not hash_inputs:
        return set()

    bound = _field_groups(hash_inputs)
    missing = visible - bound
    if missing == {"nonce_or_deadline"}:
        return set()
    return missing


def _flat_eip712_array_hash(body: str, file_text: str) -> bool:
    context = f"{file_text}\n{body}"
    if not _EIP712_FLAT_ARRAY_RE.search(context):
        return False
    return not _EIP712_RECURSIVE_GUARD_RE.search(body)


def _multisig_counts_duplicate_signers(signature: str, body: str) -> bool:
    context = f"{signature}\n{body}"
    if not (
        _SIG_COLLECTION_RE.search(context)
        and _THRESHOLD_RE.search(context)
        and _COUNT_INC_RE.search(body)
        and _AUTH_OR_VERIFY_RE.search(body)
    ):
        return False
    return not _UNIQUE_GUARD_RE.search(body)


def _skips_role_signature_validation(name: str, signature: str, body: str) -> bool:
    context = f"{name}\n{signature}\n{body}"
    if not (_SIGNATURE_PARAM_RE.search(signature) and _ROLE_OR_DOMAIN_RE.search(context)):
        return False
    if not (_ACTION_NAME_RE.search(name) or _ACTION_NAME_RE.search(body)):
        return False
    if not _STATEFUL_EFFECT_RE.search(body):
        return False
    return not _SIGNATURE_VALIDATION_RE.search(body)


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    file_text = source_nocomment(source)
    file_clean = _strip_strings(file_text)

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue

        name = fn_name(fn, source)
        body_node = fn_body(fn)
        if body_node is None:
            continue

        signature = _signature_text(fn, body_node, source)
        body = body_text_nocomment(body_node, source)
        findings: list[str] = []

        missing = _missing_domain_binding(name, signature, body, file_clean)
        if missing:
            findings.append(
                "signed digest omits " + ", ".join(sorted(missing))
            )

        if _flat_eip712_array_hash(body, file_clean):
            findings.append(
                "EIP-712 nested array hash flattens element bytes before signing"
            )

        if _multisig_counts_duplicate_signers(signature, body):
            findings.append(
                "threshold validation counts signatures without distinct signer tracking"
            )

        if _skips_role_signature_validation(name, signature, body):
            findings.append(
                "public signature-bearing action path skips role signer validation"
            )

        if not findings:
            continue

        line, col = line_col(fn)
        hits.append(
            {
                "detector_id": DETECTOR_ID,
                "attack_class": ATTACK_CLASS,
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:220],
                "message": (
                    f"fn `{name}` has signature replay domain weakness: "
                    f"{'; '.join(findings)}. "
                    f"Class: {ATTACK_CLASS}."
                ),
            }
        )

    return hits

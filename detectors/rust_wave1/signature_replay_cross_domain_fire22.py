"""
signature_replay_cross_domain_fire22.py

Rust same-class recall lift for signature-replay-cross-domain.

Provenance:
- Fire21 priority miss: multisig-threshold-passed-with-single-signature-reused-in-loop-positive.
- Fire21 priority miss: r94-loop-aa-validation-bypass-via-sig-validation-fallback-positive.
- Fire21 priority miss: r94-loop-batch-claim-no-used-flag-params-replay-positive.
- Local sibling detectors: signature_domain_or_signer_uniqueness_fire20,
  r94_loop_multisig_threshold_signature_reuse_no_dedup,
  r94_loop_aa_validation_bypass_via_sig_validation_fallback,
  r94_loop_batch_claim_no_used_flag_params_replay.

The detector only reports when a signature, threshold counter, AA fallback,
or batch claim proof can be replayed without a visible domain binding,
distinct-signer guard, pre-validation hook on both branches, or consume-once
marker.
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


DETECTOR_ID = "rust_wave1.signature_replay_cross_domain_fire22"
ATTACK_CLASS = "signature-replay-cross-domain"

_STRING_RE = re.compile(r"(?s)b?r#*\".*?\"#*|b?'(?:\\.|[^'\\])+'")

_SIGNED_CONTEXT_RE = re.compile(
    r"(?i)\b("
    r"signature|signed|signer|recover|secp256|ed25519|ecdsa|permit|"
    r"authorization|validate_user_op|user_?op|typed_?data|eip712|"
    r"domain_separator|digest|replay"
    r")\b"
)
_HASH_BUILD_RE = re.compile(
    r"(?is)\b("
    r"keccak256|sha256|blake2b|blake2s|blake3|poseidon|hash"
    r")\s*\("
)
_DIRECT_HASH_CALL_RE = re.compile(
    r"(?is)\b(?:keccak256|sha256|blake2b|blake2s|blake3|poseidon|hash)"
    r"\s*\((?P<arg>[^;{}]{0,1000})\)"
)
_LET_ASSIGN_RE = re.compile(
    r"(?is)\blet\s+(?:mut\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*(?::[^=;]+)?=\s*(?P<expr>[^;]{0,1400});"
)
_EXTEND_CALL_RE = re.compile(
    r"(?is)\b(?P<buf>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*"
    r"extend_from_slice\s*\((?P<arg>[^;{}]{0,900})\)"
)
_UPDATE_CALL_RE = re.compile(
    r"(?is)(?:\b[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?update"
    r"\s*\((?P<arg>[^;{}]{0,900})\)"
)
_DOMAIN_FIELDS = (
    ("chain_id", re.compile(r"(?i)\b(chain_?id|chainid|network_id|fork_id)\b")),
    (
        "entrypoint",
        re.compile(r"(?i)\b(entry_?point|entrypoint_address|entrypoint_addr)\b"),
    ),
    (
        "contract_or_program",
        re.compile(
            r"(?i)\b("
            r"verifying_contract|current_contract|contract_address|"
            r"program_id|address_this|target_contract|target_consumer|consumer_address"
            r")\b"
        ),
    ),
    ("nonce_or_claim", re.compile(r"(?i)\b(nonce|claim_id|params_hash|salt)\b")),
)

_SIG_COLLECTION_RE = re.compile(r"(?i)\b(signatures|sigs|sig_shares|signature_shares)\b")
_LOOP_RE = re.compile(r"(?is)\bfor\s+[A-Za-z_][A-Za-z0-9_]*\s+in\s+[^{};]+")
_THRESHOLD_RE = re.compile(
    r"(?i)\b(threshold|required_signatures|required_threshold|quorum)\b"
)
_THRESHOLD_INC_RE = re.compile(
    r"(?i)\b("
    r"acquired_threshold|valid_count|threshold_count|sig_count|approved|verified"
    r")\s*(?:\+=\s*1|=\s*[A-Za-z_][A-Za-z0-9_]*\s*\+\s*1)"
)
_AUTH_OR_VERIFY_RE = re.compile(
    r"(?i)\b("
    r"contains\s*\(|verify|recover|authorized|validators|signers|secp|ed25519|ecdsa|pubkey"
    r")\b"
)
_DISTINCT_SIGNER_GUARD_RE = re.compile(
    r"(?i)\b("
    r"seen_signer|seen_signers|seen_sig|seen_sigs|unique_signer|unique_signers|"
    r"dedup|distinct|counted_signers|already_counted|HashSet|BTreeSet"
    r")\b|\.insert\s*\([^)]*(?:signer|address|pubkey|signature|sig)"
)

_AA_FN_RE = re.compile(
    r"(?i)\b("
    r"validate_user_op|validateUserOp|is_valid_signature|isValidSignature|"
    r"validate_signature|dispatch_validation"
    r")\b"
)
_AA_SIG_BRANCH_RE = re.compile(
    r"(?i)\b("
    r"signature_validation_enabled|sig_validation_enabled|is_sig_validation|"
    r"is_signature_validation|uses_sig_validation|validation_mode|ValidationPath::Signature"
    r")\b"
)
_AA_USER_OP_RE = re.compile(r"(?i)\b(user_?op|validate_user_op|userop|UserOperation)\b")
_AA_SIG_VALIDATION_RE = re.compile(
    r"(?i)\b("
    r"validate_signature[A-Za-z0-9_]*|verify_signature[A-Za-z0-9_]*|"
    r"is_valid_signature[A-Za-z0-9_]*|[A-Za-z0-9_]*signature_path"
    r")\b"
)
_PRE_VALIDATION_HOOK_RE = re.compile(r"(?i)\b(pre_validation_hook|run_pre_validation_hooks)\s*\(")

_BATCH_CLAIM_FN_RE = re.compile(
    r"(?i)\b("
    r"batch_claim|claim_batch|execute_batch_claim|redeem_batch|redeemBatch|"
    r"redeem_deposits_and_internal_balances|redeem_internal_balances"
    r")\b"
)
_PROOF_OR_PARAMS_RE = re.compile(
    r"(?i)\b("
    r"verify_proof|verifyProof|merkle_proof|merkleProof|claim_params|"
    r"params_hash|batch_proof|proof"
    r")\b"
)
_CLAIM_EFFECT_RE = re.compile(
    r"(?i)\b(pay_out|credit|transfer|mint|release|redeem|settle|withdraw)\s*\("
)
_CONSUME_ONCE_RE = re.compile(
    r"(?i)\b("
    r"used|claimed|consumed|processed|redeemed|nonce"
    r")[A-Za-z0-9_]*(?:\s*\.\s*insert\s*\(|\s*\[|\.set\s*\(|\.save\s*\(|\s*=\s*true)"
    r"|\bmark_(?:used|claimed|consumed|processed)\s*\("
    r"|\bis_(?:used|claimed|consumed|processed)\s*\("
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


def _assignments(body: str) -> dict[str, str]:
    return {match.group("name"): match.group("expr") for match in _LET_ASSIGN_RE.finditer(body)}


def _buffer_extends(body: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for match in _EXTEND_CALL_RE.finditer(body):
        out.setdefault(match.group("buf"), []).append(match.group("arg"))
    return out


def _expand_expr(expr: str, assigns: dict[str, str], buffers: dict[str, list[str]]) -> list[str]:
    parts = [expr]
    for name, assigned in assigns.items():
        if re.search(rf"\b{re.escape(name)}\b", expr):
            parts.append(assigned)
    for name, pieces in buffers.items():
        if re.search(rf"\b{re.escape(name)}\b", expr):
            parts.extend(pieces)
    return parts


def _hash_input_text(body: str) -> str:
    assigns = _assignments(body)
    buffers = _buffer_extends(body)
    inputs: list[str] = []
    for match in _EXTEND_CALL_RE.finditer(body):
        inputs.extend(_expand_expr(match.group("arg"), assigns, buffers))
    for match in _UPDATE_CALL_RE.finditer(body):
        inputs.extend(_expand_expr(match.group("arg"), assigns, buffers))
    for match in _DIRECT_HASH_CALL_RE.finditer(body):
        inputs.extend(_expand_expr(match.group("arg"), assigns, buffers))
    return "\n".join(inputs)


def _signed_digest_missing_binding(name: str, signature: str, body: str) -> set[str]:
    context = f"{name}\n{signature}\n{body}"
    if not (_SIGNED_CONTEXT_RE.search(context) and _HASH_BUILD_RE.search(body)):
        return set()
    visible = _field_groups(context)
    if not visible:
        return set()
    hash_inputs = _hash_input_text(body)
    if not hash_inputs:
        return set()
    return visible - _field_groups(hash_inputs)


def _threshold_reuses_signature(signature: str, body: str) -> bool:
    context = f"{signature}\n{body}"
    if not (
        _SIG_COLLECTION_RE.search(context)
        and _THRESHOLD_RE.search(context)
        and _LOOP_RE.search(body)
        and _THRESHOLD_INC_RE.search(body)
        and _AUTH_OR_VERIFY_RE.search(body)
    ):
        return False
    return not _DISTINCT_SIGNER_GUARD_RE.search(body)


def _aa_sig_branch_skips_prevalidation(name: str, body: str) -> bool:
    context = f"{name}\n{body}"
    if not (_AA_FN_RE.search(name) and _AA_SIG_BRANCH_RE.search(body)):
        return False
    if not (_AA_USER_OP_RE.search(context) and _AA_SIG_VALIDATION_RE.search(body)):
        return False

    branch = re.search(
        r"(?is)\bif\b[^{}]*(?:signature_validation_enabled|sig_validation_enabled|"
        r"is_sig_validation|is_signature_validation|uses_sig_validation|"
        r"validation_mode|ValidationPath::Signature)",
        body,
    )
    hook_positions = [match.start() for match in _PRE_VALIDATION_HOOK_RE.finditer(body)]
    if len(hook_positions) >= 2:
        return False
    if branch is not None and any(pos < branch.start() for pos in hook_positions):
        return False
    return True


def _batch_claim_missing_consume_once(name: str, signature: str, body: str) -> bool:
    context = f"{name}\n{signature}\n{body}"
    if not _BATCH_CLAIM_FN_RE.search(context):
        return False
    if not (_PROOF_OR_PARAMS_RE.search(body) and _CLAIM_EFFECT_RE.search(body)):
        return False
    return not _CONSUME_ONCE_RE.search(body)


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source) or not is_pub(fn, source):
            continue

        name = fn_name(fn, source)
        body_node = fn_body(fn)
        if body_node is None:
            continue

        signature = _signature_text(fn, body_node, source)
        body = body_text_nocomment(body_node, source)
        findings: list[str] = []

        missing = _signed_digest_missing_binding(name, signature, body)
        if missing:
            findings.append(
                "signed digest omits replay binding for " + ", ".join(sorted(missing))
            )

        if _threshold_reuses_signature(signature, body):
            findings.append(
                "threshold loop counts reused signature material without distinct signer tracking"
            )

        if _aa_sig_branch_skips_prevalidation(name, body):
            findings.append(
                "AA signature-validation fallback skips pre-validation hooks used by userOp path"
            )

        if _batch_claim_missing_consume_once(name, signature, body):
            findings.append(
                "batch claim proof or params are paid without consume-once tracking"
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
                    f"fn `{name}` has replayable signature or proof semantics: "
                    f"{'; '.join(findings)}. Class: {ATTACK_CLASS}."
                ),
            }
        )

    return hits

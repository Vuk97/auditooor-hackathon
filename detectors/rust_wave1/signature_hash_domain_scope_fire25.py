"""
signature_hash_domain_scope_fire25.py

Rust detector lift for signature-hash-domain-scope-gap.

Flags public signed digest or verification helpers where replay-scope fields
are visible to the function, but the payload digest actually signed or
verified omits those fields. The detector requires signature or verification
context and hash construction context before reporting.

Detector hits are candidate evidence only, not exploit proof.
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
    source_nocomment,
)


DETECTOR_ID = "rust_wave1.signature_hash_domain_scope_fire25"
ATTACK_CLASS = "signature-hash-domain-scope-gap"

_STRING_RE = re.compile(r"(?s)b?r#*\".*?\"#*|b?'(?:\\.|[^'\\])+'")

_SIGNED_CONTEXT_RE = re.compile(
    r"(?i)\b("
    r"signature|signed|signer|verify|verification|recover|ed25519|ecdsa|"
    r"secp256|schnorr|permit|authorization|auth|message|digest|replay"
    r")\b"
)

_SIGNED_FN_RE = re.compile(
    r"(?i)("
    r"(sign|verify|validate|recover|build|compute|hash|digest).*"
    r"(signature|signed|message|digest|authorization|permit|payload|call)"
    r"|"
    r"(signature|signed|message|digest|authorization|permit|payload|call).*"
    r"(sign|verify|validate|recover|build|compute|hash|digest)"
    r")"
)

_HASH_BUILD_RE = re.compile(
    r"(?is)\b("
    r"keccak256|sha256|blake2b|blake2s|blake3|poseidon|hash|digest"
    r")\s*\("
    r"|Message::from_digest\s*\("
    r"|\.finalize\s*\("
)

_VERIFY_RE = re.compile(
    r"(?is)\b("
    r"verify_signature|verify_sig|ed25519_verify|ecdsa_verify|"
    r"secp256k1_recover|secp256r1_verify|recover_signature|"
    r"is_valid_signature|verify_callback|verify"
    r")\s*\("
)

_DIRECT_HASH_CALL_RE = re.compile(
    r"(?is)\b(?:keccak256|sha256|blake2b|blake2s|blake3|poseidon|hash|digest)"
    r"\s*\((?P<arg>[^;{}]{0,1400})\)"
)

_MESSAGE_DIGEST_RE = re.compile(
    r"(?is)Message::from_digest\s*\((?P<arg>[^;{}]{0,1000})\)"
)

_LET_ASSIGN_RE = re.compile(
    r"(?is)\blet\s+(?:mut\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*(?::[^=;]+)?=\s*(?P<expr>[^;]{0,1800});"
)

_EXTEND_CALL_RE = re.compile(
    r"(?is)\b(?P<buf>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*"
    r"(?:extend_from_slice|extend)\s*\((?P<arg>[^;{}]{0,1000})\)"
)

_PUSH_CALL_RE = re.compile(
    r"(?is)\b(?P<buf>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*"
    r"push\s*\((?P<arg>[^;{}]{0,700})\)"
)

_UPDATE_CALL_RE = re.compile(
    r"(?is)(?:\b[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?update"
    r"\s*\((?P<arg>[^;{}]{0,1000})\)"
)

_SCOPE_FIELDS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "chain_or_network",
        re.compile(
            r"(?i)\b("
            r"chain_?id|chainid|network_?id|network|fork_?id|genesis_?hash|"
            r"chain_domain"
            r")\b"
        ),
    ),
    (
        "program_or_module",
        re.compile(
            r"(?i)\b("
            r"program_?id|module_?id|pallet_?id|runtime_?module|"
            r"verifying_?contract|contract_?address|contract_?id|"
            r"target_?program|target_?module"
            r")\b"
        ),
    ),
    (
        "entrypoint",
        re.compile(
            r"(?i)\b("
            r"entry_?point|entrypoint|method_?id|method_?name|function_?selector|"
            r"instruction_?tag|instruction_?discriminant|call_?kind"
            r")\b"
        ),
    ),
    (
        "nonce",
        re.compile(
            r"(?i)\b("
            r"nonce|sig_?nonce|signature_?nonce|replay_?nonce|sequence|"
            r"sequence_?number|replay_?id|counter"
            r")\b"
        ),
    ),
    (
        "account_owner",
        re.compile(
            r"(?i)\b("
            r"account_?owner|resource_?owner|owner_?account|owner_?id|"
            r"wallet_?owner|owner|account_?id"
            r")\b"
        ),
    ),
    (
        "resource_domain",
        re.compile(
            r"(?i)\b("
            r"resource_?domain|domain_?id|domain|scope_?id|scope|asset_?id|"
            r"market_?id|pool_?id|vault_?id|resource_?id"
            r")\b"
        ),
    ),
)


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

    while changed and len(parts) < 40:
        changed = False
        for item in list(parts):
            for name, assigned in assignments.items():
                if assigned in seen:
                    continue
                if re.search(rf"\b{re.escape(name)}\b", item):
                    parts.append(assigned)
                    seen.add(assigned)
                    changed = True
            for name, pieces in buffers.items():
                if not re.search(rf"\b{re.escape(name)}\b", item):
                    continue
                for piece in pieces:
                    if piece in seen:
                        continue
                    parts.append(piece)
                    seen.add(piece)
                    changed = True

    return parts


def _digest_input_text(body: str) -> str:
    assignments = _assignments(body)
    buffers = _buffer_writes(body)
    inputs: list[str] = []

    for match in _UPDATE_CALL_RE.finditer(body):
        inputs.extend(_expand_expr(match.group("arg"), assignments, buffers))

    for match in _DIRECT_HASH_CALL_RE.finditer(body):
        inputs.extend(_expand_expr(match.group("arg"), assignments, buffers))

    for match in _MESSAGE_DIGEST_RE.finditer(body):
        inputs.extend(_expand_expr(match.group("arg"), assignments, buffers))

    for expr in assignments.values():
        if _HASH_BUILD_RE.search(expr):
            inputs.extend(_expand_expr(expr, assignments, buffers))

    return "\n".join(inputs)


def _signed_digest_candidate(name: str, signature: str, body: str) -> bool:
    context = f"{name}\n{signature}\n{body}"
    if not (_SIGNED_FN_RE.search(name) or _SIGNED_CONTEXT_RE.search(context)):
        return False
    if not _HASH_BUILD_RE.search(body):
        return False
    return bool(_VERIFY_RE.search(body) or _SIGNED_FN_RE.search(name))


def _missing_scope_fields(signature: str, body: str) -> set[str]:
    visible = _field_groups(f"{signature}\n{body}")
    if not visible:
        return set()

    digest_inputs = _digest_input_text(body)
    if not digest_inputs:
        return set()

    bound = _field_groups(digest_inputs)
    missing = visible - bound

    if missing == {"resource_domain"}:
        return set()
    if missing == {"account_owner"}:
        return set()
    return missing


def run(tree, source: bytes, filepath: str):
    hits = []
    file_nc = source_nocomment(source)
    if not (_SIGNED_CONTEXT_RE.search(file_nc) and _HASH_BUILD_RE.search(file_nc)):
        return hits

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        if not is_pub(fn, source):
            continue

        body_node = fn_body(fn)
        if body_node is None:
            continue

        name = fn_name(fn, source)
        signature = _signature_text(fn, body_node, source)
        body = body_text_nocomment(body_node, source)

        if not _signed_digest_candidate(name, signature, body):
            continue

        missing = _missing_scope_fields(signature, body)
        if not missing:
            continue

        line, col = line_col(fn)
        hits.append(
            {
                "detector_id": DETECTOR_ID,
                "attack_class": ATTACK_CLASS,
                "severity": "high",
                "file": filepath,
                "line": line,
                "col": col,
                "fn_name": name,
                "snippet": snippet_of(fn, source)[:260],
                "message": (
                    f"pub fn `{name}` matches {ATTACK_CLASS}: signed digest "
                    "material omits visible replay-scope fields "
                    f"{', '.join(sorted(missing))}. Bind chain or network, "
                    "program or module, entrypoint, nonce, owner, and resource "
                    "domain fields into the digest before signing or verifying."
                ),
            }
        )

    return hits

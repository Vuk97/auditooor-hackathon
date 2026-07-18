"""
signature_digest_missing_domain_or_entrypoint_fire17.py

Rust same-class recall lift for signature-replay-cross-domain.

Flags public signed-digest builders where replay-domain fields are visible
in the surrounding type or function, but the actual hash input omits them.
The detector is deliberately not a generic hashing detector: it requires
signature, userOp, permit, EIP-712, typed-data, authorization, or replay
context before reporting.
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
    text_of,
)


DETECTOR_ID = "rust_wave1.signature_digest_missing_domain_or_entrypoint_fire17"

_SIGNED_CONTEXT_RE = re.compile(
    r"(?i)\b("
    r"signature|signed|signer|recover|secp256|ed25519|ecrecover|"
    r"permit|authorization|authorize|auth_digest|validate_user_op|"
    r"user_?op|useroperation|typed_?data|eip712|domain_separator|"
    r"session_digest|replay"
    r")\b"
)

_SIGNED_FN_RE = re.compile(
    r"(?i)("
    r"(hash|digest|build|compute|verify|validate).*"
    r"(signature|permit|authorization|auth|user_?op|typed_?data|eip712|session)"
    r"|"
    r"(signature|permit|authorization|auth|user_?op|typed_?data|eip712|session).*"
    r"(hash|digest|build|compute|verify|validate)"
    r")"
)

_HASH_BUILD_RE = re.compile(
    r"(?is)\b("
    r"keccak256|sha256|blake2b|blake2s|blake3|poseidon|"
    r"Keccak256::new|Sha256::new|hash"
    r")\s*(?:\(|::)"
    r"|\.finalize\s*\("
)

_DIRECT_HASH_CALL_RE = re.compile(
    r"(?is)\b(?:keccak256|sha256|blake2b|blake2s|blake3|poseidon|hash)"
    r"\s*\((?P<arg>[^;{}]{0,900})\)"
)

_LET_ASSIGN_RE = re.compile(
    r"(?is)\blet\s+(?:mut\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*(?::[^=;]+)?=\s*(?P<expr>[^;]{0,1600});"
)

_UPDATE_CALL_RE = re.compile(
    r"(?is)(?:\b[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?update"
    r"\s*\((?P<arg>[^;{}]{0,900})\)"
)

_EXTEND_CALL_RE = re.compile(
    r"(?is)\b(?P<buf>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*"
    r"extend_from_slice\s*\((?P<arg>[^;{}]{0,900})\)"
)

_STRING_RE = re.compile(
    r"(?s)b?r#*\".*?\"#*|b?'(?:\\.|[^'\\])+'"
)

_DOMAIN_PATTERNS = (
    (
        "chain_id",
        re.compile(
            r"(?i)\b(chain_?id|chainid|network_id|domain_chain_id)\b"
        ),
    ),
    (
        "entrypoint",
        re.compile(r"(?i)\b(entry_?point|entrypoint_address)\b"),
    ),
    (
        "verifying_contract",
        re.compile(
            r"(?i)\b("
            r"verifying_contract|current_contract|contract_address|"
            r"address_this|program_id|target_consumer|target_contract|"
            r"consumer_address"
            r")\b"
        ),
    ),
    (
        "nonce",
        re.compile(r"(?i)\b(nonce|sig_nonce|signature_nonce|op_nonce)\b"),
    ),
    (
        "fork_domain",
        re.compile(
            r"(?i)\b(fork_id|fork_domain|domain_id|domain_salt|space)\b"
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
    return {name for name, pattern in _DOMAIN_PATTERNS if pattern.search(clean)}


def _assignments(body: str) -> dict[str, str]:
    return {m.group("name"): m.group("expr") for m in _LET_ASSIGN_RE.finditer(body)}


def _buffer_extends(body: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for match in _EXTEND_CALL_RE.finditer(body):
        out.setdefault(match.group("buf"), []).append(match.group("arg"))
    return out


def _expand_named_expr(expr: str, assigns: dict[str, str], buffers: dict[str, list[str]]) -> list[str]:
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

    for match in _UPDATE_CALL_RE.finditer(body):
        inputs.extend(_expand_named_expr(match.group("arg"), assigns, buffers))

    for match in _DIRECT_HASH_CALL_RE.finditer(body):
        inputs.extend(_expand_named_expr(match.group("arg"), assigns, buffers))

    for expr in assigns.values():
        if _HASH_BUILD_RE.search(expr):
            inputs.extend(_expand_named_expr(expr, assigns, buffers))

    return "\n".join(inputs)


def _is_signed_digest_candidate(name: str, signature: str, body: str, file_text: str) -> bool:
    fn_context = f"{name}\n{signature}\n{body}"
    if not (_SIGNED_FN_RE.search(name) or _SIGNED_CONTEXT_RE.search(fn_context)):
        return False
    if not _HASH_BUILD_RE.search(body):
        return False

    # Avoid file-wide comments or unrelated helper names making a plain hash look
    # like a replay detector hit.
    if not (
        _SIGNED_FN_RE.search(name)
        or "user_op" in fn_context.lower()
        or "useroperation" in fn_context.lower()
        or "domain_separator" in fn_context.lower()
        or "eip712" in file_text.lower()
        or "signature" in fn_context.lower()
        or "permit" in fn_context.lower()
        or "authorization" in fn_context.lower()
    ):
        return False
    return True


def _cached_domain_separator_missing_runtime_fork_domain(
    name: str,
    signature: str,
    body: str,
    file_text: str,
) -> bool:
    fn_context = f"{name}\n{signature}\n{body}"
    if not re.search(r"(?i)(typed_?data|eip712|domain_separator)", fn_context + "\n" + file_text):
        return False
    if not re.search(r"\bself\s*\.\s*domain_separator\b", body):
        return False
    if re.search(r"\bself\s*\.\s*domain_separator\s*\(", body):
        return False
    if re.search(r"(?i)\b(get_)?chain_?id\s*\(|current_chain|runtime_chain|fork_id", body):
        return False
    if not re.search(r"(?is)\bdomain_separator\s*:\s*|let\s+domain_separator\s*=", file_text):
        return False
    return True


def _missing_domain_fields(signature: str, body: str, file_text: str) -> set[str]:
    visible = _field_groups(f"{signature}\n{body}\n{file_text}")
    if not visible:
        return set()

    hash_inputs = _hash_input_text(body)
    if not hash_inputs:
        return set()

    bound = _field_groups(hash_inputs)
    missing = visible - bound

    # Salt alone is not enough to report. It is often a fixed EIP-712 component
    # and is only replay-load-bearing when another replay-domain field is also
    # missing.
    if missing == {"fork_domain"}:
        return set()
    return missing


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    file_text = source.decode("utf-8", errors="replace")
    file_nc = _strip_strings(file_text)

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
        if not _is_signed_digest_candidate(name, signature, body, file_nc):
            continue

        missing = _missing_domain_fields(signature, body, file_nc)
        stale_domain = _cached_domain_separator_missing_runtime_fork_domain(
            name,
            signature,
            body,
            file_nc,
        )

        if stale_domain:
            missing.add("runtime_chain_or_fork_domain")

        if not missing:
            continue

        line, col = line_col(fn)
        hits.append(
            {
                "detector_id": DETECTOR_ID,
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:220],
                "message": (
                    f"pub fn `{name}` builds or verifies signed replay-domain "
                    "digest material without binding "
                    f"{', '.join(sorted(missing))}. The same signature can "
                    "be replayed across chains, fork domains, contracts, "
                    "entrypoints, or nonce spaces."
                ),
            }
        )

    return hits

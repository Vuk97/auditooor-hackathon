"""
rust_bridge_replay_domain_fire33.py

Rust detector lift for bridge-proof-domain-bypass and
signature-replay-cross-domain replay namespaces.

Fire33 closes the Rust bridge replay-domain miss family called out by:
- reports/detector_lift_fire32_20260605/post_priorities_rust.md
- reference/patterns.dsl/bridge-proof-domain-bypass-umbrella.yaml
- reference/patterns.dsl/bridge-replay-key-omits-chain-domain.yaml
- reference/patterns.dsl/bridge-proof-domain-bypass-ballot-field-omitted.yaml

The detector reports public bridge, light-client, router, or attestation
handlers that expose route/domain coordinates but build the replay key,
payload id, commitment hash, or signed transcript from message material only.
It requires a replay-state write or a signature verification path before
reporting.
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


DETECTOR_ID = "rust_wave1.rust_bridge_replay_domain_fire33"
ATTACK_CLASS = "bridge-proof-domain-bypass"

_STRING_RE = re.compile(r"(?s)b?r#*\".*?\"#*|b?'(?:\\.|[^'\\])+'")

_BRIDGE_CONTEXT_RE = re.compile(
    r"(?i)\b("
    r"bridge|cross[_-]?chain|gateway|portal|router|route|relay|relayer|"
    r"endpoint|channel|lane|light[_-]?client|client|attestation|"
    r"verifier|proof|commitment|payload|message|packet|transcript"
    r")\b"
)

_FN_CONTEXT_RE = re.compile(
    r"(?i)("
    r"(process|receive|handle|execute|finalize|settle|claim|release|relay|"
    r"verify|validate|submit|consume|record|mark|dispatch)"
    r".*(bridge|message|payload|packet|proof|attestation|signature|"
    r"commitment|transcript|replay|route)"
    r"|bridge.*(receive|execute|process|proof|message|payload|replay|verify)"
    r"|verify.*(bridge|message|attestation|signature|payload|transcript)"
    r")"
)

_MESSAGE_MATERIAL_RE = re.compile(
    r"(?i)\b("
    r"nonce|sequence|seq|message|msg|payload|payload_hash|message_hash|"
    r"packet|packet_hash|proof|proof_hash|root|leaf|commitment|"
    r"attestation|signature|sender|validator|body|data|calldata|"
    r"withdrawal|transfer_id|claim_id"
    r")\b"
)

_HASH_BUILD_RE = re.compile(
    r"(?is)\b("
    r"keccak256|sha256|sha3|blake2b|blake2s|blake3|poseidon|"
    r"hash|digest|message_id|payload_id|replay_key|commitment_hash"
    r")\s*\("
    r"|[A-Za-z0-9_]+::digest\s*\("
    r"|\.finalize\s*\("
)

_DIRECT_HASH_CALL_RE = re.compile(
    r"(?is)\b(?:keccak256|sha256|sha3|blake2b|blake2s|blake3|poseidon|"
    r"hash|digest|message_id|payload_id|replay_key|commitment_hash)"
    r"\s*\((?P<arg>[^;{}]{0,1400})\)"
    r"|[A-Za-z0-9_]+::digest\s*\((?P<assoc_arg>[^;{}]{0,1400})\)"
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

_REPLAY_STATE_WRITE_RE = re.compile(
    r"(?is)\b(?P<target>[A-Za-z_][A-Za-z0-9_\.]*?)\s*\.\s*"
    r"(?P<method>insert|set|save|mark_processed|mark_consumed|"
    r"mark_used|record|put)\s*\((?P<args>[^;]{0,1400});"
    r"|(?P<index_target>\b[A-Za-z_][A-Za-z0-9_\.]*"
    r"(?:processed|consumed|used|seen|executed|settled|claimed|"
    r"replay)[A-Za-z0-9_\.]*)\s*\[[^\]]+\]\s*=\s*(?:true|1)"
)

_REPLAY_TARGET_RE = re.compile(
    r"(?i)\b("
    r"processed[A-Za-z0-9_]*|consumed[A-Za-z0-9_]*|used[A-Za-z0-9_]*|"
    r"seen[A-Za-z0-9_]*|executed[A-Za-z0-9_]*|settled[A-Za-z0-9_]*|"
    r"claimed[A-Za-z0-9_]*|replay[A-Za-z0-9_]*|"
    r"message_ids|payload_ids|commitments|nonces|receipts"
    r")\b"
)

_VERIFY_RE = re.compile(
    r"(?is)\b("
    r"verify_signature|verify_sig|verify_attestation|verify_message|"
    r"verify_payload|verify_proof|verify_commitment|authenticate|"
    r"ed25519_verify|ecdsa_verify|secp256k1_verify|recover"
    r")\s*\((?P<args>[^;{}]{0,1400})\)"
)

_SAFE_DOMAIN_RE = re.compile(
    r"(?i)\b("
    r"domain_separated|domain_separator|bind_domain|scope_domain|"
    r"domain_bound|scoped_replay_key|scoped_message_id|bridge_replay_key|"
    r"route_bound_key|verify_domain|WrongDomain|WrongDestination|"
    r"InvalidDomain|InvalidDestination"
    r")\b"
)

_DOMAIN_FIELDS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "source_chain",
        re.compile(
            r"(?i)\b(source_chain|src_chain|from_chain|origin_chain|"
            r"remote_chain|source_chain_id|src_chain_id|origin_chain_id|"
            r"from_chain_id|remote_chain_id)\b"
        ),
    ),
    (
        "destination_chain",
        re.compile(
            r"(?i)\b(destination_chain|dest_chain|dst_chain|target_chain|"
            r"local_chain|destination_chain_id|dest_chain_id|dst_chain_id|"
            r"target_chain_id|local_chain_id)\b"
        ),
    ),
    (
        "source_domain",
        re.compile(
            r"(?i)\b(source_domain|src_domain|origin_domain|from_domain|"
            r"remote_domain|source_domain_id|src_domain_id|origin_domain_id)\b"
        ),
    ),
    (
        "destination_domain",
        re.compile(
            r"(?i)\b(destination_domain|dest_domain|dst_domain|target_domain|"
            r"local_domain|destination_domain_id|dest_domain_id|"
            r"target_domain_id|local_domain_id)\b"
        ),
    ),
    (
        "endpoint_or_channel",
        re.compile(
            r"(?i)\b(endpoint|endpoint_id|src_endpoint|dst_endpoint|"
            r"channel|channel_id|lane|lane_id|route|route_id|port_id)\b"
        ),
    ),
    (
        "receiver_or_app",
        re.compile(
            r"(?i)\b(receiver|recipient|receiver_app|recipient_app|"
            r"application_domain|app_domain|app_id|destination_app|"
            r"verifying_contract|verifier_domain)\b"
        ),
    ),
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


def _hash_input_text(body: str) -> str:
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
    for expr in assignments.values():
        if _HASH_BUILD_RE.search(expr):
            inputs.extend(_expand_expr(expr, assignments, buffers))

    return "\n".join(inputs)


def _replay_state_writes(body: str) -> list[str]:
    writes = []
    for match in _REPLAY_STATE_WRITE_RE.finditer(body):
        call = match.group(0)
        target = match.group("target") or match.group("index_target") or ""
        args = match.group("args") or call
        if not (_REPLAY_TARGET_RE.search(target) or _REPLAY_TARGET_RE.search(call)):
            continue
        writes.append(args)
    return writes


def _verify_inputs(body: str) -> str:
    assignments = _assignments(body)
    buffers = _buffer_writes(body)
    inputs: list[str] = []
    for match in _VERIFY_RE.finditer(body):
        inputs.extend(_expand_expr(match.group("args"), assignments, buffers))
    return "\n".join(inputs)


def _missing_fields(visible: set[str], candidate_inputs: str) -> set[str]:
    if not visible or not candidate_inputs:
        return set()
    bound = _domain_groups(candidate_inputs)
    return visible - bound


def _replay_key_missing_domain(
    signature: str,
    body: str,
    visible: set[str],
) -> set[str]:
    if not _replay_state_writes(body):
        return set()
    if not (_HASH_BUILD_RE.search(body) and _MESSAGE_MATERIAL_RE.search(body)):
        return set()
    if _SAFE_DOMAIN_RE.search(body):
        return set()
    return _missing_fields(visible, _hash_input_text(body))


def _signature_transcript_missing_domain(
    name: str,
    signature: str,
    body: str,
    visible: set[str],
) -> set[str]:
    context = f"{name}\n{signature}\n{body}"
    if not re.search(r"(?i)(signature|attestation|signed|transcript|validator)", context):
        return set()
    if not (_VERIFY_RE.search(body) and _HASH_BUILD_RE.search(body)):
        return set()
    if _SAFE_DOMAIN_RE.search(body):
        return set()

    inputs = "\n".join([_hash_input_text(body), _verify_inputs(body)])
    return _missing_fields(visible, inputs)


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
        fn_text = f"{name}\n{signature}\n{body}"
        if not (_FN_CONTEXT_RE.search(name) or _BRIDGE_CONTEXT_RE.search(fn_text)):
            continue

        visible = _domain_groups(fn_text)
        if not visible:
            continue

        findings: list[str] = []
        replay_missing = _replay_key_missing_domain(signature, body, visible)
        if replay_missing:
            findings.append(
                "replay key omits "
                + ", ".join(sorted(replay_missing))
            )

        signature_missing = _signature_transcript_missing_domain(
            name,
            signature,
            body,
            visible,
        )
        if signature_missing:
            findings.append(
                "signature transcript omits "
                + ", ".join(sorted(signature_missing))
            )

        if not findings:
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
                "snippet": snippet_of(fn, source)[:240],
                "message": (
                    f"pub fn `{name}` matches {ATTACK_CLASS}: "
                    f"{'; '.join(findings)}. Bind source, destination, "
                    "endpoint, channel, receiver, and app domain fields into "
                    "the replay key, commitment hash, payload id, or signed "
                    "attestation transcript."
                ),
            }
        )

    return hits

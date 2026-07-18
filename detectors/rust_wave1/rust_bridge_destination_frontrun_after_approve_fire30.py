"""
rust_bridge_destination_frontrun_after_approve_fire30.py

Rust bridge-proof-domain-bypass detector for destination frontrun and replay
after approval.

Flags public Rust bridge outbound functions where a caller supplies a
destination, route, lane, or channel field, the function consumes an owner
approval or bridge authorization, and the consumed authorization does not bind
those destination fields. This covers the Solodit Gains Trade bridgeNft shape
and the broader bridge-domain class where the destination is checked outside
the consumed authorization or outbound message id.

Source refs:
  - reports/detector_lift_fire29_20260605/post_priorities_rust.md
  - reference/patterns.dsl/r94-loop-bridge-destination-frontrun-after-approve.yaml
  - reference/patterns.dsl/bridge-replay-key-omits-chain-domain.yaml
  - reference/patterns.dsl/bridge-proof-domain-bypass-umbrella.yaml
  - reference/patterns.dsl.r99_map_butter_bridge_20260520/message-in-success-with-zero-amount-mints-token.yaml

Detector hits are candidate evidence only. They are NOT_SUBMIT_READY and need
normal R40, R76, and R80 proof discipline before filing work.
"""

from __future__ import annotations

import os
import pathlib
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


DETECTOR_ID = "rust_wave1.rust_bridge_destination_frontrun_after_approve_fire30"
ATTACK_CLASS = "bridge-proof-domain-bypass"
SUBMISSION_POSTURE = "NOT_SUBMIT_READY"

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive"}

_BRIDGE_FN_RE = re.compile(
    r"(?i)\b("
    r"bridge|send|transfer|dispatch|outbound|relay|message|remote|xchain|"
    r"cross_chain|crosschain|mint|withdraw"
    r")"
)

_BRIDGE_CONTEXT_RE = re.compile(
    r"(?i)\b("
    r"bridge|cross[_-]?chain|gateway|portal|relay|relayer|outbox|outbound|"
    r"message|packet|dispatch|channel|lane|route|destination|remote|"
    r"proof|attestation"
    r")\b"
)

_DEST_GROUP_PATTERNS = (
    (
        "destination",
        re.compile(
            r"\b("
            r"destination|dest|dst|receiver|recipient|target_address|"
            r"to_address|remote_receiver|remote_recipient|to"
            r")\b",
            re.IGNORECASE,
        ),
    ),
    (
        "destination_chain",
        re.compile(
            r"\b("
            r"destination_chain|dest_chain|dst_chain|target_chain|"
            r"remote_chain|destination_chain_id|dest_chain_id|dst_chain_id"
            r")\b",
            re.IGNORECASE,
        ),
    ),
    (
        "destination_domain",
        re.compile(
            r"\b("
            r"destination_domain|dest_domain|dst_domain|target_domain|"
            r"remote_domain|destination_domain_id|dest_domain_id"
            r")\b",
            re.IGNORECASE,
        ),
    ),
    (
        "channel_or_lane",
        re.compile(
            r"\b("
            r"channel|channel_id|lane|lane_id|route|route_id|endpoint|"
            r"endpoint_id|bridge_lane|bridge_channel"
            r")\b",
            re.IGNORECASE,
        ),
    ),
)

_REQUEST_DEST_RE = re.compile(
    r"(?is)\b(?:request|req|msg|message|payload|params|order|transfer)"
    r"\s*\.\s*"
    r"(?:destination|dest|dst|receiver|recipient|channel|lane|route|"
    r"target|remote)"
)

_AUTH_OR_APPROVAL_RE = re.compile(
    r"(?is)\b("
    r"require_auth|require_auth_for_args|transfer_from|transferFrom|"
    r"allowance|approve|approved|approval|permit|authorization|authorisation|"
    r"signature|nonce|consume_approval|use_authorization|spend_allowance|"
    r"consume_authorization|processed|consumed|used"
    r")\b"
)

_OWNER_TRANSFER_RE = re.compile(
    r"(?is)("
    r"(?:transfer_from|transferFrom)\s*\(\s*&?\s*"
    r"(?:owner|token_owner|nft_owner|current_owner)"
    r"|(?:owner_of|ownerOf)\s*\([^;{}]{0,220}\)[^;]{0,260}"
    r"(?:transfer_from|transferFrom)"
    r")"
)

_CALLER_OWNER_BOUND_RE = re.compile(
    r"(?is)("
    r"(?:env\s*\.\s*invoker\s*\(\s*\)|caller|sender|msg_sender\s*\(\s*\)|"
    r"info\s*\.\s*sender|who)\s*(?:==|!=)\s*&?\s*"
    r"(?:owner|token_owner|nft_owner|current_owner)"
    r"|(?:owner|token_owner|nft_owner|current_owner)\s*(?:==|!=)\s*&?\s*"
    r"(?:env\s*\.\s*invoker\s*\(\s*\)|caller|sender|msg_sender\s*\(\s*\)|"
    r"info\s*\.\s*sender|who)"
    r"|(?:ensure|require|assert)(?:_eq|_ne)?!?\s*\([^;{}]{0,520}"
    r"(?:caller|sender|msg_sender|env\s*\.\s*invoker|info\s*\.\s*sender|who)"
    r"[^;{}]{0,520}(?:owner|token_owner|nft_owner|current_owner)"
    r")"
)

_AUTH_FOR_ARGS_RE = re.compile(
    r"(?is)\b(?:[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?"
    r"require_auth_for_args\s*\([^;{}]{0,1400}\)"
)

_AUTH_BINDING_CALL_RE = re.compile(
    r"(?is)\b("
    r"verify|validate|check|consume|bind|authorize|authorise"
    r")_(?:bridge_)?(?:authorization|authorisation|auth|approval|permit|"
    r"signature|message|destination|route)\s*\([^;{}]{0,1400}\)"
)

_HASH_CALL_RE = re.compile(
    r"(?is)\b(?:keccak256|sha256|blake2(?:b|s)?|blake3|poseidon|digest|hash)"
    r"\s*\([^;{}]{0,1400}\)"
)

_LET_ASSIGN_RE = re.compile(
    r"(?is)\blet\s+(?:mut\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*(?::[^=;]+)?=\s*(?P<expr>[^;]{0,1800});"
)

_HASH_CORE_FIELD_RE = re.compile(
    r"(?i)\b("
    r"owner|token_owner|nft_owner|token_id|nft_id|amount|nonce|payload|"
    r"payload_hash|message|message_id|authorization|approval|permit|"
    r"recipient|receiver|sender|account"
    r")\b"
)

_CONSUME_OR_OUTBOUND_RE = re.compile(
    r"(?is)("
    r"(?:processed|consumed|used|spent|seen|sent|executed)"
    r"[A-Za-z0-9_]*\s*\.\s*(?:insert|set|save|put)\s*\("
    r"|(?:outbox|outbound|messages?|packets?|dispatches?)"
    r"[A-Za-z0-9_]*\s*\.\s*(?:push|insert|enqueue|send)\s*\("
    r"|\b(?:send|dispatch|enqueue|emit|submit|relay)_"
    r"(?:bridge_)?(?:message|packet|transfer|payload)\s*\("
    r"|transfer_from\s*\(|transferFrom\s*\("
    r")"
)


def _dest_groups(text: str) -> set[str]:
    return {
        name
        for name, pattern in _DEST_GROUP_PATTERNS
        if pattern.search(text)
    }


def _signature_text(fn, body, source: bytes) -> str:
    return source[fn.start_byte:body.start_byte].decode("utf-8", errors="replace")


def _assignments(body: str) -> dict[str, str]:
    return {
        match.group("name"): match.group("expr")
        for match in _LET_ASSIGN_RE.finditer(body)
    }


def _expand_hash_expr(expr: str, assignments: dict[str, str]) -> list[str]:
    parts = [expr]
    for name, assigned in assignments.items():
        if re.search(rf"\b{re.escape(name)}\b", expr):
            parts.append(assigned)
    return parts


def _hash_inputs(body: str) -> list[str]:
    assignments = _assignments(body)
    inputs: list[str] = []

    for expr in assignments.values():
        if _HASH_CALL_RE.search(expr):
            inputs.extend(_expand_hash_expr(expr, assignments))

    for match in _HASH_CALL_RE.finditer(body):
        inputs.extend(_expand_hash_expr(match.group(0), assignments))

    return inputs


def _auth_binds_destination(body: str, visible_dest: set[str]) -> bool:
    for match in _AUTH_FOR_ARGS_RE.finditer(body):
        if visible_dest & _dest_groups(match.group(0)):
            return True

    for match in _AUTH_BINDING_CALL_RE.finditer(body):
        call = match.group(0)
        if visible_dest & _dest_groups(call):
            return True

    return False


def _hash_omits_destination(body: str, visible_dest: set[str]) -> set[str]:
    hash_inputs = _hash_inputs(body)
    if not hash_inputs:
        return set()

    best_dest_groups: set[str] = set()
    saw_core_hash = False
    for expr in hash_inputs:
        if not _HASH_CORE_FIELD_RE.search(expr):
            continue
        saw_core_hash = True
        best_dest_groups = max(best_dest_groups, _dest_groups(expr), key=len)

    if not saw_core_hash:
        return set()

    return visible_dest - best_dest_groups


def _function_has_destination_surface(signature: str, body: str) -> set[str]:
    visible = _dest_groups(signature)
    if visible:
        return visible

    if _REQUEST_DEST_RE.search(body):
        return _dest_groups(body)

    return set()


def _scan_function(fn, source: bytes, filepath: str) -> dict | None:
    if in_test_cfg(fn, source) or not is_pub(fn, source):
        return None

    name = fn_name(fn, source)
    body_node = fn_body(fn)
    if body_node is None:
        return None

    signature = _signature_text(fn, body_node, source)
    body = body_text_nocomment(body_node, source)
    fn_text = f"{name}\n{signature}\n{body}"

    if not (_BRIDGE_FN_RE.search(name) or _BRIDGE_CONTEXT_RE.search(fn_text)):
        return None

    visible_dest = _function_has_destination_surface(signature, body)
    if not visible_dest:
        return None

    if not _AUTH_OR_APPROVAL_RE.search(body):
        return None

    if _auth_binds_destination(body, visible_dest):
        return None

    owner_transfer_gap = (
        _OWNER_TRANSFER_RE.search(body) is not None
        and _CALLER_OWNER_BOUND_RE.search(body) is None
    )

    omitted_from_hash = _hash_omits_destination(body, visible_dest)
    outbound_replay_gap = (
        bool(omitted_from_hash)
        and _CONSUME_OR_OUTBOUND_RE.search(body) is not None
    )

    if not (owner_transfer_gap or outbound_replay_gap):
        return None

    line, col = line_col(fn)
    reason_bits: list[str] = []
    if owner_transfer_gap:
        reason_bits.append(
            "moves an owner asset after approval without caller or argument binding"
        )
    if outbound_replay_gap:
        reason_bits.append(
            "builds or consumes an outbound bridge id without binding "
            + ", ".join(sorted(omitted_from_hash))
        )

    return {
        "detector_id": DETECTOR_ID,
        "attack_class": ATTACK_CLASS,
        "submission_posture": SUBMISSION_POSTURE,
        "severity": "high",
        "file": filepath,
        "line": line,
        "col": col,
        "fn_name": name,
        "destination_groups": sorted(visible_dest),
        "snippet": snippet_of(fn, source)[:220],
        "message": (
            f"pub fn `{name}` accepts bridge destination or channel fields "
            "but the consumed approval or outbound authorization does not "
            "bind them: "
            + "; ".join(reason_bits)
            + f". Candidate {ATTACK_CLASS}; {SUBMISSION_POSTURE}."
        ),
    }


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn in function_items(tree.root_node):
        hit = _scan_function(fn, source, filepath)
        if hit is not None:
            hits.append(hit)
    return hits


def scan_file(filepath: str) -> list[dict]:
    try:
        source = pathlib.Path(filepath).read_bytes()
    except OSError:
        return []

    try:
        import importlib.util

        engine_path = pathlib.Path(__file__).resolve().parents[1] / ".." / "tools" / "ast-engine.py"
        engine_path = engine_path.resolve()
        spec = importlib.util.spec_from_file_location("ast_engine", engine_path)
        if spec is None or spec.loader is None:
            return []
        ast_engine = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ast_engine)
        tree = ast_engine.AstEngine("rust", source).parse()
    except Exception:
        return []

    return run(tree, source, filepath)


def scan(root: str) -> list[tuple[str, int, str]]:
    results: list[tuple[str, int, str]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [dirname for dirname in dirnames if dirname not in _SKIP_DIRS]
        for filename in filenames:
            if not filename.endswith(".rs"):
                continue
            path = os.path.join(dirpath, filename)
            for hit in scan_file(path):
                results.append((hit["file"], hit["line"], hit["message"]))
    return results


if __name__ == "__main__":
    import sys

    root = sys.argv[1] if len(sys.argv) > 1 else "."
    for file_path, line, message in scan(root):
        print(f"{file_path}:{line}:{DETECTOR_ID}:{message}")

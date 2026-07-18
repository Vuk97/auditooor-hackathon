"""
bridge_queue_message_domain_unbound_fire10.py

Flags Rust bridge relay or queue handlers that verify message/proof
material, then enqueue, release, or consume the accepted message under a
queue key or digest that carries no visible bridge domain context.

Fire10 lift target: bridge-proof-domain-bypass, queue-message variant.
This detector is narrower than the sibling proof-root and message-hash
detectors. It requires the handler to perform both:
  1. a message/proof verification step, and
  2. a queue, release, processed, consumed, or settlement state write.

The hit fires when visible route/source/destination/receiver domain inputs
exist in the handler but the load-bearing queue key or proof digest is
unbound to any of those domains.
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


DETECTOR_ID = "rust_wave1.bridge_queue_message_domain_unbound_fire10"

_FN_NAME_RE = re.compile(
    r"(?i)("
    r"(relay|receive|process|handle|submit|verify|validate|finalize|settle|"
    r"consume|release|enqueue|queue|dispatch)"
    r".*(bridge|message|packet|proof|receipt|relay|queue)"
    r"|bridge.*(relay|receive|process|message|packet|queue|release)"
    r"|message.*(relay|receive|process|queue|release|consume)"
    r")"
)

_BRIDGE_CONTEXT_RE = re.compile(
    r"(?i)\b("
    r"bridge|cross[_-]?chain|gateway|portal|relay|relayer|"
    r"message|packet|payload|proof|receipt|root|commitment"
    r")\b"
)

_PROOF_OR_MESSAGE_RE = re.compile(
    r"(?i)\b("
    r"proof|attestation|signature|receipt|root|state_root|storage_root|"
    r"commitment|leaf|message|msg|packet|payload|header|merkle"
    r")\b"
)

_VERIFY_RE = re.compile(
    r"(?is)\b(?:[A-Za-z0-9_]+::|[A-Za-z0-9_\.]+\.)?"
    r"(?:verify|verify_message|verify_proof|verify_packet|verify_receipt|"
    r"verify_merkle|verify_root|validate|validate_message|check_proof|"
    r"authenticate|prove)[A-Za-z0-9_]*\s*\([^;{}]{0,900}\)"
)

_STATE_TARGET_RE = re.compile(
    r"(?i)("
    r"pending|queue|queued|inbox|outbox|relay|relayed|message|messages|"
    r"packet|packets|processed|consumed|released|settled|executed|"
    r"receipt|receipts|dispatch|dispatches"
    r")"
)

_STATE_WRITE_RE = re.compile(
    r"(?is)\b(?P<target>[A-Za-z_][A-Za-z0-9_\.]*)\s*\.\s*"
    r"(?P<method>insert|set|push|push_back|append|enqueue|add_to_queue|"
    r"mark_processed|mark_consumed|consume|release)\s*\("
    r"(?P<args>[^;]{0,1200});"
)

_DIGEST_RE = re.compile(
    r"(?is)\b(?:[A-Za-z0-9_]*hash[A-Za-z0-9_]*|keccak256|sha256|"
    r"blake2(?:b|s)?|blake3|digest)\s*\([^;{}]{0,900}\)"
)

_SAFE_BINDING_RE = re.compile(
    r"(?i)\b("
    r"domain_separated|domain_separator|bind_domain|with_domain|"
    r"scoped_bridge_queue_key|bridge_queue_key|message_domain_key|"
    r"route_message_key|scoped_message_key|domain_bound_message_key|"
    r"verify_domain|InvalidDomain|WrongDomain|WrongDestination"
    r")\b"
)

_DOMAIN_GROUP_PATTERNS = (
    ("route", re.compile(r"\broute(?:_id)?\b", re.IGNORECASE)),
    ("lane", re.compile(r"\blane(?:_id)?\b", re.IGNORECASE)),
    ("channel", re.compile(r"\bchannel(?:_id)?\b", re.IGNORECASE)),
    ("client", re.compile(r"\b(?:client(?:_id)?|light_client_id|ref_client_id)\b", re.IGNORECASE)),
    ("bridge", re.compile(r"\bbridge(?:_id)?\b", re.IGNORECASE)),
    ("source_chain", re.compile(r"\b(?:source_chain|src_chain|from_chain|origin_chain)\b", re.IGNORECASE)),
    ("source_domain", re.compile(r"\b(?:source_domain|src_domain|origin_domain|remote_domain)\b", re.IGNORECASE)),
    ("destination_chain", re.compile(r"\b(?:destination_chain|dest_chain|dst_chain|target_chain|local_chain)\b", re.IGNORECASE)),
    ("destination_domain", re.compile(r"\b(?:destination_domain|dest_domain|dst_domain|target_domain|local_domain)\b", re.IGNORECASE)),
    ("receiver", re.compile(r"\b(?:receiver_domain|receiver_chain|receiver_app|application_domain|app_domain)\b", re.IGNORECASE)),
    ("chain_id", re.compile(r"\b(?:chain_id|chainid|network_id)\b", re.IGNORECASE)),
)


def _domain_groups(text: str) -> set[str]:
    return {
        name
        for name, pattern in _DOMAIN_GROUP_PATTERNS
        if pattern.search(text)
    }


def _signature_text(fn, body, source: bytes) -> str:
    return source[fn.start_byte:body.start_byte].decode("utf-8", errors="replace")


def _verify_calls(text: str) -> list[str]:
    return [
        match.group(0)
        for match in _VERIFY_RE.finditer(text)
        if _PROOF_OR_MESSAGE_RE.search(match.group(0))
    ]


def _state_writes(text: str) -> list[str]:
    writes = []
    for match in _STATE_WRITE_RE.finditer(text):
        call = match.group(0)
        target = match.group("target")
        method = match.group("method")
        if not (_STATE_TARGET_RE.search(target) or method in {"enqueue", "add_to_queue"}):
            continue
        writes.append(call)
    return writes


def _unbound_digest(text: str) -> str | None:
    for match in _DIGEST_RE.finditer(text):
        expr = match.group(0)
        if not _PROOF_OR_MESSAGE_RE.search(expr):
            continue
        if _SAFE_BINDING_RE.search(expr):
            continue
        if _domain_groups(expr):
            continue
        return expr
    return None


def _unbound_state_write(writes: list[str]) -> str | None:
    for write in writes:
        if _SAFE_BINDING_RE.search(write):
            continue
        if _domain_groups(write):
            continue
        return write
    return None


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        if not is_pub(fn, source):
            continue

        name = fn_name(fn, source)
        body = fn_body(fn)
        if body is None:
            continue

        body_nc = body_text_nocomment(body, source)
        signature = _signature_text(fn, body, source)
        fn_text = f"{signature}\n{body_nc}"

        if not (_FN_NAME_RE.search(name) or _BRIDGE_CONTEXT_RE.search(fn_text)):
            continue
        visible_domains = _domain_groups(fn_text)
        if not visible_domains:
            continue
        if not _verify_calls(body_nc):
            continue

        writes = _state_writes(body_nc)
        if not writes:
            continue

        unbound_write = _unbound_state_write(writes)
        unbound_digest = _unbound_digest(body_nc)
        if unbound_write is None and unbound_digest is None:
            continue

        reason = "queue key" if unbound_write is not None else "proof digest"
        line, col = line_col(fn)
        hits.append(
            {
                "detector_id": DETECTOR_ID,
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:220],
                "message": (
                    f"pub fn `{name}` verifies bridge message/proof material "
                    f"and writes accepted relay state with an unbound {reason}. "
                    f"Visible domain context ({', '.join(sorted(visible_domains))}) "
                    "is not carried by the queue key or digest, so a message "
                    "accepted in one route, chain, or receiver domain can be "
                    "queued, released, or consumed in another domain."
                ),
            }
        )

    return hits

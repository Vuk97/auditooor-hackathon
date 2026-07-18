"""
bridge_proof_domain_bypass_fire6.py

Flags Rust bridge proof, receipt, or commitment verifiers that accept a
source, destination, receiver, route, or client domain but derive the accepted
proof digest or leaf from proof material only.

Fire6 lift evidence:
- reference/patterns.dsl/bridge-proof-domain-bypass-verifier-digest-omits-domain.yaml
- reference/patterns.dsl/bridge-proof-leaf-omits-source-destination-domain.yaml
- reference/patterns.dsl/bridge-receiver-domain-omitted-from-proof-digest.yaml
- reports/realworld_recall_drilldown_slice43_final_bridgeproof.md

This detector is intentionally narrower than generic bridge message replay
detectors. It requires proof/root/receipt material plus an actual verification
or consumed-key path, then checks whether the digest or accepted leaf omits
visible bridge domain coordinates.
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


_FN_NAME_RE = re.compile(
    r"(?i)("
    r"(verify|validate|check|consume|process|finalize|submit|relay|prove|apply)"
    r".*(bridge|proof|root|receipt|commitment|message|packet|export)"
    r"|bridge.*(proof|root|receipt|commitment|verify|consume)"
    r"|proof.*(root|receipt|verify|consume|commitment)"
    r")"
)

_BRIDGE_CONTEXT_RE = re.compile(
    r"(?i)\b("
    r"bridge|cross[_-]?chain|gateway|portal|relay|relayer|"
    r"proof|receipt|merkle|root|commitment|export|message|packet"
    r")\b"
)

_PROOF_MATERIAL_RE = re.compile(
    r"(?i)\b("
    r"proof|proof_root|root|state_root|storage_root|header_root|"
    r"receipt_root|receipt|commitment_root|commitment|leaf|leaf_hash|"
    r"proof_hash|message_hash|payload_hash|export_root|header|mmr|merkle"
    r")\b"
)

_HASH_EXPR_RE = re.compile(
    r"(?is)\b(?:[A-Za-z0-9_]*hash[A-Za-z0-9_]*|"
    r"keccak256|sha256|blake2(?:b|s)?|blake3|digest)"
    r"\s*\([^;{}]{0,720}\)"
)

_VERIFY_OR_CONSUME_RE = re.compile(
    r"\b(?:[A-Za-z0-9_]+::)?(?:"
    r"verify|verify_proof|verify_merkle|verify_merkle_proof|"
    r"check_proof|validate_proof|consume_proof|verify_root|"
    r"verify_commitment|verify_header|insert|set"
    r")\s*\([^;{}]{0,720}\)"
    r"|\b(?:consumed|processed|used|spent|seen|settled|executed)"
    r"[A-Za-z0-9_]*\s*(?:\.insert|\.set|\[)\s*[^;{}]{0,520}",
    re.IGNORECASE | re.DOTALL,
)

_DOMAIN_GUARD_RE = re.compile(
    r"(?i)\b("
    r"domain_separator|domain_separated|bind_domain|scope_domain|"
    r"with_domain|verify_domain|InvalidDomain|WrongDomain|WrongDestination"
    r")\b"
)

_DOMAIN_GROUP_PATTERNS = (
    ("lane", re.compile(r"\blane(?:_id)?\b", re.IGNORECASE)),
    ("channel", re.compile(r"\bchannel(?:_id)?\b", re.IGNORECASE)),
    ("route", re.compile(r"\broute(?:_id)?\b", re.IGNORECASE)),
    ("client", re.compile(r"\b(?:client(?:_id)?|light_client_id|ref_client_id)\b", re.IGNORECASE)),
    ("bridge", re.compile(r"\bbridge(?:_id)?\b", re.IGNORECASE)),
    ("source_chain", re.compile(r"\b(?:source_chain|src_chain|from_chain|origin_chain)\b", re.IGNORECASE)),
    ("source_domain", re.compile(r"\b(?:source_domain|src_domain|origin_domain|remote_domain)\b", re.IGNORECASE)),
    ("destination_chain", re.compile(r"\b(?:destination_chain|dest_chain|dst_chain|target_chain|local_chain)\b", re.IGNORECASE)),
    ("destination_domain", re.compile(r"\b(?:destination_domain|dest_domain|dst_domain|target_domain|local_domain)\b", re.IGNORECASE)),
    ("receiver", re.compile(r"\b(?:receiver_domain|application_domain|app_domain|export_domain|receiver_app)\b", re.IGNORECASE)),
    ("chain_id", re.compile(r"\b(?:chain_id|chainid|network_id)\b", re.IGNORECASE)),
    ("settlement", re.compile(r"\b(?:settlement(?:_domain|_id|_context)?|settle_context)\b", re.IGNORECASE)),
    ("verifier", re.compile(r"\b(?:verifying_contract|verifier_domain|domain_id)\b", re.IGNORECASE)),
)


def _domain_groups(text: str) -> set[str]:
    return {
        name
        for name, pattern in _DOMAIN_GROUP_PATTERNS
        if pattern.search(text)
    }


def _signature_text(fn, body, source: bytes) -> str:
    return source[fn.start_byte:body.start_byte].decode("utf-8", errors="replace")


def _candidate_hash_exprs(text: str) -> list[str]:
    return [
        match.group(0)
        for match in _HASH_EXPR_RE.finditer(text)
        if _PROOF_MATERIAL_RE.search(match.group(0))
        and not _DOMAIN_GUARD_RE.search(match.group(0))
    ]


def _has_acceptance_path(text: str) -> bool:
    if not _PROOF_MATERIAL_RE.search(text):
        return False
    return _VERIFY_OR_CONSUME_RE.search(text) is not None


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        if not is_pub(fn, source):
            continue

        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        fn_text = source[fn.start_byte:fn.end_byte].decode("utf-8", errors="replace")
        if not _BRIDGE_CONTEXT_RE.search(fn_text):
            continue

        body_nc = body_text_nocomment(body, source)
        signature = _signature_text(fn, body, source)
        visible_domains = _domain_groups(signature)
        if not visible_domains:
            continue
        if not _has_acceptance_path(body_nc):
            continue

        for expr in _candidate_hash_exprs(body_nc):
            expr_domains = _domain_groups(expr)
            omitted = visible_domains - expr_domains
            if not omitted:
                continue

            line, col = line_col(fn)
            hits.append(
                {
                    "severity": "high",
                    "line": line,
                    "col": col,
                    "snippet": snippet_of(fn, source)[:220],
                    "message": (
                        f"pub fn `{name}` accepts bridge proof domain context "
                        f"but derives the accepted proof digest or leaf without "
                        f"binding {', '.join(sorted(omitted))}. The same proof "
                        f"material may be replayed under another bridge domain."
                    ),
                }
            )
            break

    return hits

"""
r94_loop_bridge_proof_root_missing_domain_binding.py

Flags Rust bridge proof or root verifiers that receive lane, chain,
client, route, domain, or settlement context but verify a proof root,
leaf, commitment, or consumed hash without binding those context fields
into the checked digest.

Local source evidence:
- reference/patterns.dsl/bridge-proof-domain-bypass-verifier-digest-omits-domain.yaml
- reference/patterns.dsl/bridge-proof-leaf-omits-source-destination-domain.yaml
- reference/patterns.dsl/bridge-receiver-domain-omitted-from-proof-digest.yaml
- reports/realworld_recall_drilldown_bridge-proof-domain-bypass.json

This is narrower than the sibling message replay-key detector. It targets
proof/root verification and consumption, not message-id construction.
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
    r"(verify|validate|check|consume|process|finalize|submit|relay|prove|settle)"
    r".*(bridge|cross|proof|root|commitment|receipt|message|header|packet)"
    r"|bridge.*(proof|root|verify|consume|settle)"
    r"|proof.*(root|verify|consume|settle)"
    r"|root.*(verify|consume|settle)"
    r")"
)

_BRIDGE_PROOF_CONTEXT_RE = re.compile(
    r"(?i)\b("
    r"bridge|cross[_-]?chain|gateway|portal|relay|relayer|"
    r"lane|route|client|settlement|proof|merkle|root|commitment"
    r")\b"
)

_PROOF_MATERIAL_RE = re.compile(
    r"(?i)\b("
    r"proof|proof_root|root|state_root|storage_root|header_root|"
    r"receipt_root|commitment_root|leaf|leaf_hash|proof_hash|"
    r"message_hash|payload_hash|commitment|receipt|header|mmr|merkle"
    r")\b"
)

_HASH_EXPR_RE = re.compile(
    r"(?i)\b(?:keccak256|sha256|blake2(?:b|s)?|hash|digest)"
    r"\s*\([^;{}]{0,520}\)",
    re.DOTALL,
)

_VERIFY_EXPR_RE = re.compile(
    r"(?i)\b(?:[A-Za-z0-9_]+::)?(?:"
    r"verify|verify_proof|verify_merkle|verify_merkle_proof|"
    r"check_proof|validate_proof|consume_proof|verify_root|"
    r"verify_commitment|verify_header"
    r")\s*\([^;{}]{0,520}\)",
    re.DOTALL,
)

_CONSUME_EXPR_RE = re.compile(
    r"(?i)\b(?:consumed|processed|used|spent|seen|settled|executed)"
    r"[A-Za-z0-9_]*\s*(?:\.insert|\.set|\[)\s*[^;{}]{0,420}",
    re.DOTALL,
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
    ("chain_id", re.compile(r"\b(?:chain_id|chainid|network_id)\b", re.IGNORECASE)),
    ("settlement", re.compile(r"\b(?:settlement(?:_domain|_id|_context)?|settle_context)\b", re.IGNORECASE)),
    ("application", re.compile(r"\b(?:application_domain|app_domain|receiver_domain|export_domain)\b", re.IGNORECASE)),
    ("verifier", re.compile(r"\b(?:verifying_contract|verifier_domain|domain_separator|domain_id)\b", re.IGNORECASE)),
)


def _domain_groups(text: str) -> set[str]:
    return {
        name
        for name, pattern in _DOMAIN_GROUP_PATTERNS
        if pattern.search(text)
    }


def _candidate_exprs(pattern: re.Pattern[str], text: str) -> list[str]:
    return [
        match.group(0)
        for match in pattern.finditer(text)
        if _PROOF_MATERIAL_RE.search(match.group(0))
    ]


def _first_omitted_context(
    expressions: list[str],
    visible_domains: set[str],
) -> tuple[str, set[str]] | None:
    for expr in expressions:
        expr_domains = _domain_groups(expr)
        omitted = visible_domains - expr_domains
        if omitted:
            return expr, omitted
    return None


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
        body_nc = body_text_nocomment(body, source)
        if not _BRIDGE_PROOF_CONTEXT_RE.search(fn_text):
            continue
        if not _PROOF_MATERIAL_RE.search(body_nc):
            continue

        visible_domains = _domain_groups(fn_text)
        if not visible_domains:
            continue

        hash_exprs = _candidate_exprs(_HASH_EXPR_RE, body_nc)
        hash_omission = _first_omitted_context(hash_exprs, visible_domains)
        if hash_omission is not None:
            _expr, omitted = hash_omission
        elif hash_exprs:
            continue
        else:
            verify_exprs = _candidate_exprs(_VERIFY_EXPR_RE, body_nc)
            consume_exprs = _candidate_exprs(_CONSUME_EXPR_RE, body_nc)
            fallback_omission = _first_omitted_context(
                verify_exprs + consume_exprs,
                visible_domains,
            )
            if fallback_omission is None:
                continue
            _expr, omitted = fallback_omission

        line, col = line_col(fn)
        hits.append(
            {
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:220],
                "message": (
                    f"pub fn `{name}` verifies or consumes bridge proof/root "
                    f"material without binding visible domain context into "
                    f"the checked digest ({', '.join(sorted(omitted))}). "
                    f"A proof root valid for one lane, chain, client, or "
                    f"settlement context may be replayed in another context."
                ),
            }
        )

    return hits

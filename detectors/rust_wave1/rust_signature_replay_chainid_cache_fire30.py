"""
rust_signature_replay_chainid_cache_fire30.py

Fire30 Rust detector for signature-replay-cross-domain stale cache misses.

Flags public signature verification paths that reuse a chain id, fork id,
channel id, domain id, or domain separator cached at init time without a
live runtime recheck or dynamic domain rebuild.

Provenance:
- reports/detector_lift_fire29_20260605/post_priorities_rust.md
- reference/patterns.dsl/eip712-cached-domain-separator-handrolled.yaml
- reference/patterns.dsl/bridge-replay-key-omits-chain-domain.yaml
- reference/patterns.dsl.r73_eip7702/eip7702-permit-auth-replay-post-revoke.yaml

Class: signature-replay-cross-domain.
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


DETECTOR_ID = "rust_wave1.rust_signature_replay_chainid_cache_fire30"
ATTACK_CLASS = "signature-replay-cross-domain"

_STRING_RE = re.compile(r"(?s)b?r#*\".*?\"#*|b?'(?:\\.|[^'\\])+'")

_CACHE_FIELD_SRC = (
    r"(?:"
    r"(?:cached|stored|initial|deployment|genesis|init)[A-Za-z0-9_]*"
    r"(?:chain_?id|chainid|fork_?id|channel_?id|domain_?id|domain_separator)"
    r"|domain_separator|cached_domain_separator|stored_domain_separator"
    r"|trusted_channel_id|local_channel_id|source_channel_id|dest_channel_id"
    r"|src_channel_id|dst_channel_id|source_domain_id|destination_domain_id"
    r")"
)

_CONST_CACHE_SRC = (
    r"(?:CACHED_CHAIN_ID|CACHED_CHAINID|INITIAL_CHAIN_ID|DEPLOYMENT_CHAIN_ID|"
    r"GENESIS_CHAIN_ID|CACHED_FORK_ID|INITIAL_FORK_ID|CACHED_CHANNEL_ID|"
    r"INITIAL_CHANNEL_ID|TRUSTED_CHANNEL_ID|LOCAL_CHANNEL_ID|"
    r"DOMAIN_SEPARATOR|CACHED_DOMAIN_SEPARATOR|STORED_DOMAIN_SEPARATOR|"
    r"CACHED_DOMAIN_ID|INITIAL_DOMAIN_ID)"
)

_INIT_FN_RE = re.compile(
    r"(?i)\b(new|init|initialize|constructor|setup|bootstrap|deploy_init|"
    r"init_domain|initialize_eip712|configure_domain)\b"
)

_SELF_ASSIGN_RE = re.compile(
    fr"(?is)\bself\s*\.\s*(?P<field>{_CACHE_FIELD_SRC})\s*=\s*"
    r"(?P<rhs>[^;]{0,900});"
)
_STRUCT_ASSIGN_RE = re.compile(
    fr"(?is)\b(?P<field>{_CACHE_FIELD_SRC})\s*:\s*"
    r"(?P<rhs>[^,}\n]{0,900})"
)
_CONST_ASSIGN_RE = re.compile(
    fr"(?is)\b(?:const|static)\s+(?P<field>{_CONST_CACHE_SRC})\b"
    r"[^=]{0,200}=\s*(?P<rhs>[^;]{0,900});"
)

_DOMAIN_RHS_RE = re.compile(
    r"(?i)\b(chain_?id|chainid|fork_?id|channel_?id|domain_?id|"
    r"domain_separator|network_id|compute_domain|build_domain|"
    r"env|ctx|ledger|genesis|verifying_contract|program_id)\b"
)

_BODY_CACHED_USE_RE = re.compile(
    fr"(?is)\bself\s*\.\s*(?P<self>{_CACHE_FIELD_SRC})\b"
    fr"|\bSelf\s*::\s*(?P<assoc>{_CONST_CACHE_SRC})\b"
    fr"|\b(?P<const>{_CONST_CACHE_SRC})\b"
)

_SIGNATURE_CONTEXT_RE = re.compile(
    r"(?i)\b(signature|sig|signed|signer|recover|secp256|ecdsa|ed25519|"
    r"permit|authorization|typed_?data|eip712|domain_separator|"
    r"validate|verify|message_hash|digest)\b"
)
_VERIFY_OR_HASH_RE = re.compile(
    r"(?is)\b(keccak256|sha256|blake2b|blake2s|blake3|poseidon|hash|"
    r"digest|recover_signer|recover|verify_signature|check_signature|"
    r"ed25519_verify|secp256k1_recover|ecdsa_recover|\.verify\s*\()"
)

_SAFE_DYNAMIC_DOMAIN_RE = re.compile(
    r"(?is)\b("
    r"_?domain_separator_v4|build_domain_separator|compute_domain_separator|"
    r"recompute_domain|rebuild_domain|refresh_domain|domain_for_chain|"
    r"current_chain_id|get_chain_id|runtime_chain_id|env\s*\.\s*chain_id|"
    r"env::chain_id|ctx\s*\.\s*chain_id|ledger\s*\(\s*\)\s*\.\s*network_id|"
    r"current_fork_id|get_fork_id|runtime_fork_id|"
    r"current_channel_id|get_channel_id|runtime_channel_id|channel_registry"
    r")\b"
)

_SAFE_COMPARE_RE = re.compile(
    r"(?is)\b(assert_eq|assert|ensure|require)!?\s*\([^;{}]{0,500}"
    r"(chain_?id|chainid|fork_?id|channel_?id|domain_?id)"
    r"[^;{}]{0,500}(current|runtime|env|ctx|ledger|packet|message|msg)"
)


def _blank(match: re.Match[str]) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in match.group(0))


def _strip_strings(text: str) -> str:
    return _STRING_RE.sub(_blank, text)


def _signature_text(fn, body, source: bytes) -> str:
    return source[fn.start_byte:body.start_byte].decode("utf-8", errors="replace")


def _field_kind(name: str) -> str:
    lower = name.lower()
    if "domain_separator" in lower:
        return "domain_separator"
    if "chainid" in lower or "chain_id" in lower:
        return "chain_id"
    if "fork_id" in lower or "forkid" in lower:
        return "fork_id"
    if "channel_id" in lower or "channelid" in lower:
        return "channel_id"
    if "domain_id" in lower or "domainid" in lower:
        return "domain_id"
    return "domain"


def _cache_evidence_from_init(tree, source: bytes, file_text: str) -> set[str]:
    evidence: set[str] = set()

    for match in _CONST_ASSIGN_RE.finditer(file_text):
        field = match.group("field")
        rhs = match.group("rhs")
        if _DOMAIN_RHS_RE.search(field) or _DOMAIN_RHS_RE.search(rhs):
            evidence.add(_field_kind(field))

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        name = fn_name(fn, source)
        if not _INIT_FN_RE.search(name):
            continue
        body_node = fn_body(fn)
        if body_node is None:
            continue
        body = _strip_strings(body_text_nocomment(body_node, source))
        for pattern in (_SELF_ASSIGN_RE, _STRUCT_ASSIGN_RE):
            for match in pattern.finditer(body):
                field = match.group("field")
                rhs = match.group("rhs")
                if _DOMAIN_RHS_RE.search(field) or _DOMAIN_RHS_RE.search(rhs):
                    evidence.add(_field_kind(field))

    return evidence


def _used_cached_kinds(body: str) -> set[str]:
    used: set[str] = set()
    for match in _BODY_CACHED_USE_RE.finditer(body):
        name = match.group("self") or match.group("assoc") or match.group("const")
        used.add(_field_kind(name))
    return used


def _is_signature_verification_path(name: str, signature: str, body: str) -> bool:
    context = f"{name}\n{signature}\n{body}"
    return bool(_SIGNATURE_CONTEXT_RE.search(context) and _VERIFY_OR_HASH_RE.search(body))


def _has_live_recheck(body: str) -> bool:
    return bool(_SAFE_DYNAMIC_DOMAIN_RE.search(body) or _SAFE_COMPARE_RE.search(body))


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    file_text = _strip_strings(source_nocomment(source))
    cached_kinds = _cache_evidence_from_init(tree, source, file_text)
    if not cached_kinds:
        return hits

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source) or not is_pub(fn, source):
            continue

        name = fn_name(fn, source)
        body_node = fn_body(fn)
        if body_node is None:
            continue

        signature = _signature_text(fn, body_node, source)
        body = _strip_strings(body_text_nocomment(body_node, source))
        if not _is_signature_verification_path(name, signature, body):
            continue

        reused_cached = _used_cached_kinds(body) & cached_kinds
        if not reused_cached:
            continue
        if _has_live_recheck(body):
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
                    f"pub fn `{name}` verifies signed material using cached "
                    f"{', '.join(sorted(reused_cached))} without a live "
                    "chain, fork, channel, or domain rebuild. Signatures can "
                    "replay across forks or channel/domain changes. "
                    f"Class: {ATTACK_CLASS}."
                ),
            }
        )

    return hits

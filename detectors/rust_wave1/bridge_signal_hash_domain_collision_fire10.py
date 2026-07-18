"""
bridge_signal_hash_domain_collision_fire10.py

Flags Rust bridge release paths where a signal or message hash authorizes
custody movement but the hash preimage omits visible bridge release domains
such as chain, route, bridge address, receiver, or entrypoint.

Confirmed corpus anchors:
- audit/corpus_tags/tags/dsl_pattern_r94-loop-bridge-signal-hash-value-not-bound-c0994222cb7a.yaml
- audit/corpus_tags/tags/case_studies_local/verus-ethereum-bridge-proof-binding-2026-05/record.yaml
- tools/tests/test_hackerman_etl_from_darknavy_web3.py

This is intentionally distinct from the existing Rust bridge detectors:
- bridge_proof_domain_bypass_fire6 targets proof/root digest omission.
- r94_loop_bridge_message_hash_missing_lane_or_chain_domain targets nonce
  plus payload replay keys.
- r94_loop_bridge_signal_hash_value_not_bound targets value omission.

Fire10 targets signal or message hashes that gate value release while omitting
release domains that determine where the bridged value may move.
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
    r"(release|withdraw|claim|finalize|settle|process|execute|dispatch|redeem|payout)"
    r".*(signal|message|bridge|gateway|inbound|outbound|cross)"
    r"|(signal|message).*(release|withdraw|claim|settle|process|execute|dispatch|payout)"
    r")"
)

_BRIDGE_CONTEXT_RE = re.compile(
    r"(?i)\b("
    r"bridge|cross[_-]?chain|gateway|portal|relay|relayer|"
    r"signal|message|inbound|outbound|settlement|escrow|custody"
    r")\b"
)

_HASH_EXPR_RE = re.compile(
    r"(?is)\b(?:"
    r"keccak256|sha256|blake2(?:b|s)?|blake3|digest|"
    r"[A-Za-z0-9_]*hash[A-Za-z0-9_]*"
    r")\s*\([^;{}]{0,760}\)"
)

_HASH_RELEASE_MATERIAL_RE = re.compile(
    r"(?i)\b("
    r"signal|message|payload|token|asset|currency|amount|value|fee|"
    r"release|withdraw|payout|recipient|receiver"
    r")\b"
)

_AUTHORIZATION_RE = re.compile(
    r"(?is)("
    r"\b(?:assert|ensure|require)\s*!\s*\([^;{}]*(?:signal|message|hash)"
    r"|\b(?:verify|validate|check|consume|accept)[A-Za-z0-9_]*"
    r"\s*\([^;{}]*(?:signal|message|hash)"
    r"|\b(?:accepted|authorized|approved|valid|trusted|seen|used|processed|consumed)"
    r"[A-Za-z0-9_]*\s*\.\s*(?:contains|get|remove|insert|set)"
    r"\s*\([^;{}]*(?:signal|message|hash)"
    r")"
)

_CUSTODY_MOVEMENT_RE = re.compile(
    r"(?is)(?:"
    r"\.\s*(?:transfer|safe_transfer|mint|release|withdraw|payout|pay|credit)"
    r"\s*\([^;{}]*(?:receiver|recipient|to|amount|value|token|asset)"
    r"|\b(?:transfer|safe_transfer|mint|release|withdraw|payout|pay|credit)"
    r"\s*\([^;{}]*(?:receiver|recipient|to|amount|value|token|asset)"
    r")"
)

_DOMAIN_GUARD_RE = re.compile(
    r"(?i)\b("
    r"domain_separator|domain_separated|bind_domain|scope_domain|"
    r"with_domain|verify_domain|InvalidDomain|WrongDomain"
    r")\b"
)

_DOMAIN_GROUP_PATTERNS = (
    (
        "chain",
        re.compile(
            r"\b(?:"
            r"source_chain|src_chain|from_chain|origin_chain|"
            r"destination_chain|dest_chain|dst_chain|target_chain|local_chain|"
            r"chain_id|chainid|network_id"
            r")\b",
            re.IGNORECASE,
        ),
    ),
    (
        "route",
        re.compile(
            r"\b(?:route(?:_id)?|lane(?:_id)?|channel(?:_id)?|path(?:_id)?)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "bridge",
        re.compile(
            r"\b(?:"
            r"bridge_(?:address|addr|id|contract)|"
            r"bridge_address|bridge_addr|bridge_id|"
            r"gateway_address|gateway_addr|portal_address|portal_addr|"
            r"verifying_contract"
            r")\b",
            re.IGNORECASE,
        ),
    ),
    (
        "receiver",
        re.compile(
            r"\b(?:"
            r"receiver|recipient|recipient_address|receiver_address|"
            r"to_address|beneficiary|destination_account"
            r")\b",
            re.IGNORECASE,
        ),
    ),
    (
        "entrypoint",
        re.compile(
            r"\b(?:"
            r"entrypoint|entry_point|selector|function_selector|"
            r"handler|handler_id|message_type|action|action_id|call_type"
            r")\b",
            re.IGNORECASE,
        ),
    ),
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
    exprs = []
    for match in _HASH_EXPR_RE.finditer(text):
        expr = match.group(0)
        if _DOMAIN_GUARD_RE.search(expr):
            continue
        if not _HASH_RELEASE_MATERIAL_RE.search(expr):
            continue
        exprs.append(expr)
    return exprs


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

        body_nc = body_text_nocomment(body, source)
        signature = _signature_text(fn, body, source)
        fn_text = f"{signature}\n{body_nc}"
        if not _BRIDGE_CONTEXT_RE.search(fn_text):
            continue
        if not _AUTHORIZATION_RE.search(body_nc):
            continue
        if not _CUSTODY_MOVEMENT_RE.search(body_nc):
            continue

        visible_domains = _domain_groups(fn_text)
        if not visible_domains:
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
                        f"pub fn `{name}` releases bridge custody using a "
                        f"signal or message hash that omits "
                        f"{', '.join(sorted(omitted))} domain fields. "
                        f"The same accepted signal can authorize value "
                        f"movement in another release context."
                    ),
                }
            )
            break

    return hits

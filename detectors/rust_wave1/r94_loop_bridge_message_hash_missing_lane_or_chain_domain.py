"""
r94_loop_bridge_message_hash_missing_lane_or_chain_domain.py

Flags bridge message digest builders that hash nonce or sequence plus
payload bytes, but omit lane, client, or chain-domain coordinates from
the same digest preimage.

Confirmed corpus anchors:
- hyperbridge-local:domain-separated-message-hash-gap-HIGH
- corpus-mined:rust-bridge-replay-on-unscoped-message-id:c1e607ef6c8f

This stays narrower than the Solidity bridge finality/domain detectors:
it does not look at state-root finality or validator-set transcript
binding, only at Rust message-id / replay-key construction where a bridge
route reuses nonce space across lanes or source chains.
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
    r"bridge.*(hash|digest|message|dispatch|id)"
    r"|message.*(hash|digest|id)"
    r"|dispatch.*(hash|digest|id)"
    r"|compute_.*message.*(hash|digest|id)"
    r"|hash_.*message"
    r"|verify_.*message"
    r")"
)

_HASH_CALL_RE = re.compile(
    r"(keccak256|sha256|blake2(?:b|s)?|digest|hash)\s*\([^;]{0,240}\)",
    re.IGNORECASE | re.DOTALL,
)

_CORE_REPLAY_FIELDS_RE = re.compile(
    r"\b(nonce|message_id|msg_id|sequence|seq_no)\b",
    re.IGNORECASE,
)

_PAYLOAD_FIELDS_RE = re.compile(
    r"\b(payload|payload_hash|message_hash|commitment|leaf)\b",
    re.IGNORECASE,
)

_DOMAIN_FIELDS_RE = re.compile(
    r"\b("
            r"lane(?:_id)?|channel(?:_id)?|route(?:_id)?|"
            r"client(?:_id)?|ref_client_id|light_client_id|"
            r"source_chain|src_chain|source_domain|origin_domain|"
            r"destination_chain|dest_chain|dst_chain|"
            r"destination_domain|dest_domain|dst_domain|"
            r"destination_id|dest_id|dst_id|"
            r"origin|source|chain_id"
    r")\b",
    re.IGNORECASE,
)

_DOMAIN_GROUP_PATTERNS = (
    ("lane", re.compile(r"\blane(?:_id)?\b", re.IGNORECASE)),
    ("channel", re.compile(r"\bchannel(?:_id)?\b", re.IGNORECASE)),
    ("route", re.compile(r"\broute(?:_id)?\b", re.IGNORECASE)),
    ("client", re.compile(r"\b(?:client(?:_id)?|ref_client_id|light_client_id)\b", re.IGNORECASE)),
    ("source_chain", re.compile(r"\b(?:source_chain|src_chain)\b", re.IGNORECASE)),
    ("source_domain", re.compile(r"\b(?:source_domain|origin_domain)\b", re.IGNORECASE)),
    ("destination_chain", re.compile(r"\b(?:destination_chain|dest_chain|dst_chain)\b", re.IGNORECASE)),
    ("destination_domain", re.compile(r"\b(?:destination_domain|dest_domain|dst_domain)\b", re.IGNORECASE)),
    ("destination_id", re.compile(r"\b(?:destination_id|dest_id|dst_id)\b", re.IGNORECASE)),
    ("origin", re.compile(r"\borigin\b", re.IGNORECASE)),
    ("source", re.compile(r"\bsource\b", re.IGNORECASE)),
    ("chain_id", re.compile(r"\bchain_id\b", re.IGNORECASE)),
)


def _domain_groups(text: str) -> set[str]:
    return {
        name
        for name, pattern in _DOMAIN_GROUP_PATTERNS
        if pattern.search(text)
    }


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
        visible_domains = _domain_groups(fn_text)
        if not visible_domains:
            continue

        flagged = False
        missing_domains: set[str] = set()
        for match in _HASH_CALL_RE.finditer(body_nc):
            digest_expr = match.group(0)
            if not _CORE_REPLAY_FIELDS_RE.search(digest_expr):
                continue
            if not _PAYLOAD_FIELDS_RE.search(digest_expr):
                continue
            digest_domains = _domain_groups(digest_expr)
            omitted_domains = visible_domains - digest_domains
            if not omitted_domains:
                continue
            missing_domains = omitted_domains
            flagged = True
            break

        if not flagged:
            continue

        line, col = line_col(fn)
        hits.append(
            {
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:220],
                "message": (
                    f"pub fn `{name}` builds a bridge replay key from "
                    f"nonce or sequence plus payload material without lane, "
                    f"client, source-chain, or destination-chain domain "
                    f"binding ({', '.join(sorted(missing_domains))}). Reused nonce "
                    f"space across routes can replay the same message digest "
                    f"on a different bridge lane."
                ),
            }
        )

    return hits

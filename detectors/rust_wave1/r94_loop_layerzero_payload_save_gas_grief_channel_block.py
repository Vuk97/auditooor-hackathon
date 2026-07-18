"""
r94_loop_layerzero_payload_save_gas_grief_channel_block.py

Flags lzReceive / failure-storage fns that persist a failed
payload into a dynamic-sized mapping / vector keyed by
(srcChain, srcAddr, nonce) without a max-size bound or a
fixed-size summary hash. Attacker sends a huge payload whose
SSTORE cost during failure-save consumes all gas, bricking the
channel.

Source: Solodit #27506 (Code4rena Tapioca DAO BaseUSDO).
Class: layerzero-payload-save-gas-grief-channel-block (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(lz_receive|lzReceive|"
    r"_store_failed_message|_storeFailedMessage|"
    r"save_failed_payload|store_failed_payload|"
    r"persist_failed_message)"
)
# Must write the raw payload into a mapping / vector (SSTORE-cost scales with size).
_STORE_RAW_RE = re.compile(
    fr"(?i)({IDENT}failed_messages\s*\[[^\]]*\]\s*=\s*{IDENT}payload|"
    fr"{IDENT}failedMessages\s*\[[^\]]*\]\s*=\s*{IDENT}payload|"
    fr"(failed_messages|failedMessages|stored_payloads|storedPayloads|pending_payloads|pendingPayloads)\s*\.\s*insert\s*\([^)]*\bpayload\b|"
    fr"storedPayloads\s*\[[^\]]*\]\s*=\s*StoredPayload\s*\(\s*{IDENT}payload|"
    fr"storage\s*\.\s*set\s*\(\s*&?{IDENT}key\s*,\s*&?{IDENT}payload\s*\))"
)
# Safe: stores a fixed-size digest (hash) instead of the raw payload,
# or enforces a max payload size before saving.
_DIGEST_OR_CAP_RE = re.compile(
    fr"(?i)(keccak\w*\s*\(\s*{IDENT}payload|sha256\s*\(\s*{IDENT}payload|"
    fr"payloadHash\s*=|payload_hash\s*=|"
    fr"{IDENT}payload\.len\s*\(\s*\)\s*(<=|<)\s*\d+|"
    fr"{IDENT}payload\.length\s*(<=|<)\s*\d+|"
    fr"require\s*\(\s*{IDENT}payload\.length\s*(<=|<)|"
    fr"assert\w*\s*!?\s*\(\s*{IDENT}payload\.len\s*\(\s*\)\s*(<=|<))"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        if not _STORE_RAW_RE.search(body_nc):
            continue
        if _DIGEST_OR_CAP_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` persists a raw LZ failure-payload "
                f"into a dynamic mapping whose SSTORE cost scales "
                f"with payload size, and has no payload-length cap — "
                f"attacker sends an oversized payload that drains all "
                f"gas in the failure-save path, bricking the channel "
                f"(layerzero-payload-save-gas-grief-channel-block). "
                f"See Solodit #27506 (Code4rena Tapioca DAO BaseUSDO)."
            ),
        })
    return hits

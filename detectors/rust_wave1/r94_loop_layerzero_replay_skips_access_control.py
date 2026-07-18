"""
r94_loop_layerzero_replay_skips_access_control.py

Flags LayerZero / cross-chain retry / replay fns that re-invoke
the inner `_receiveMessage` / `_handle_message` directly,
bypassing the access-control / source-verification modifier that
guards the entry point. Replay becomes a privilege-escalation
vector: anyone can re-drive a stored payload.

Source: Solodit #48243 (OtterSec Olympus DAO CrossChainBridge).
Class: layerzero-replay-skips-access-control (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(retry_message|replay_message|retry_payload|"
    r"retry_failed_message|resubmit_message|redrive)"
)
# Directly invokes the inner receive.
_INNER_CALL_RE = re.compile(
    r"(?i)(_receive_message\s*\(|_receiveMessage\s*\(|"
    r"_handle_message\s*\(|_handleMessage\s*\(|"
    r"_blocking_lz_receive\s*\(|_blockingLzReceive\s*\(|"
    r"_nonblocking_lz_receive\s*\(|_nonblockingLzReceive\s*\()"
)
# Safe: access control / source verification re-applied.
_AUTH_RE = re.compile(
    fr"(?i)(only_endpoint|onlyEndpoint|"
    fr"require\s*\(\s*msg\.sender\s*==\s*{IDENT}lzEndpoint|"
    fr"require\s*\(\s*{IDENT}lzEndpoint\s*\(\s*\)\s*==\s*msg\.sender|"
    fr"require_auth\s*\(\s*&?\s*{IDENT}endpoint|"
    fr"trustedRemoteLookup\[\s*{IDENT}srcChain\s*\]|"
    fr"is_trusted_remote|require\s*\(\s*isTrustedRemote|"
    fr"access_control\.check|check_caller_is_endpoint|"
    fr"verify_source|source_verified)"
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
        if not _INNER_CALL_RE.search(body_nc):
            continue
        if _AUTH_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` retries / replays a stored LZ "
                f"payload by calling `_receiveMessage` / "
                f"`_handleMessage` directly without re-verifying the "
                f"endpoint / trustedRemote source — anyone can "
                f"re-drive stored payloads, bypassing access control "
                f"(layerzero-replay-skips-access-control). "
                f"See Solodit #48243 (OtterSec Olympus DAO)."
            ),
        })
    return hits

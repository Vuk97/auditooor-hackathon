"""
r94_loop_bridge_pause_only_tokens_not_attestation_layer.py

Flags bridge pause/freeze/sweep/shutdown fns that halt token-level
transfers but do NOT also pause the OApp's verify/commitVerification
attestation layer — attacker can still commit further attestations
post-freeze.

Source: Kelp rsETH exploit (banteg gist).
Class: bridge-pause-only-tokens-not-attestation-layer (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(
    r"(?i)(pause|freeze|emergency_pause|emergencyPause|"
    r"sweep|shutdown|disable_transfers|disableTransfers|halt)"
)
_TOKEN_PAUSE_RE = re.compile(
    r"(paused\s*=\s*true|"
    r"_paused\s*=\s*true|"
    r"token_paused\s*=\s*true|"
    r"transfer_paused\s*=\s*true|"
    r"sweep_recipient|sweepRecipient|"
    r"blacklist\s*\[\s*\w+\s*\]\s*=\s*true|"
    r"blacklist\s*\.\s*insert\s*\(|"
    r"ban_address)"
)
_ATTESTATION_PAUSE_RE = re.compile(
    r"(verify_paused\s*=\s*true|"
    r"commit_paused\s*=\s*true|"
    r"attestation_paused\s*=\s*true|"
    r"endpoint\.pause\s*\(|"
    r"oapp\.pause\s*\(|"
    r"pause_receive_library|pauseReceiveLibrary|"
    r"lzReceive_paused\s*=\s*true|"
    r"bridge_fully_paused\s*=\s*true|"
    r"full_stop|emergency_circuit_break_attestation)"
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
        if not _TOKEN_PAUSE_RE.search(body_nc):
            continue
        if _ATTESTATION_PAUSE_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn {name} pauses only token-level transfers but "
                f"does NOT pause the OApp's verify/commitVerification "
                f"attestation layer — attacker can still commit further "
                f"attestations post-freeze "
                f"(bridge-pause-only-tokens-not-attestation-layer). "
                f"Kelp rsETH nonce 309 was committed AFTER sweep."
            ),
        })
    return hits

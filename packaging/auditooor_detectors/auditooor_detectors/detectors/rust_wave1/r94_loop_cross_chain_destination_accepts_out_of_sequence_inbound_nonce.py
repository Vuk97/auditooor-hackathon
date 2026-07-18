"""
r94_loop_cross_chain_destination_accepts_out_of_sequence_inbound_nonce.py

Flags cross-chain destination receive fns (lz_receive, handle_message,
receive_message) that consume an inbound nonce without enforcing strict
sequential increment (lastNonce + 1) or echoing the source-side
outbound nonce — attacker-attested out-of-sequence nonce (e.g. dst 308
while src still 307) slips through.

Source: Kelp rsETH exploit.
Class: cross-chain-destination-accepts-out-of-sequence-inbound-nonce (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(
    r"(?i)(lz_receive|lzReceive|_lz_receive|_lzReceive|"
    r"handle_message|handleMessage|receive_message|receiveMessage)"
)
_NONCE_USE_RE = re.compile(
    r"(\b(nonce|inbound_nonce|inboundNonce)\b\s*[,:=]|"
    r"params\.\s*nonce|message\.\s*nonce|"
    r"origin\.\s*nonce|origin\s*\.\s*nonce)"
)
_SEQUENCE_CHECK_RE = re.compile(
    fr"(require\s*\(\s*{IDENT}nonce\s*==\s*{IDENT}(expected_nonce|lastNonce|last_nonce)\s*\+\s*1|"
    fr"assert\w*\s*!?\s*\(\s*{IDENT}nonce\s*==\s*{IDENT}(lastNonce|last_nonce)\s*\+\s*1|"
    fr"lastNonce\s*=\s*{IDENT}nonce\s*;|"
    fr"last_nonce\s*=\s*{IDENT}nonce\s*;|"
    r"source_outbound_nonce|sourceOutboundNonce|"
    fr"nextNonce\s*=\s*{IDENT}nonce\s*\+\s*1|"
    r"strict_sequence_check|enforce_monotonic_nonce|"
    r"nonce\s*==\s*lastNonce\s*\+\s*1)"
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
        if not _NONCE_USE_RE.search(body_nc):
            continue
        if _SEQUENCE_CHECK_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn {name} accepts an inbound-nonce message without "
                f"enforcing strict sequential increment (lastNonce+1) or "
                f"echoing the source-side outbound nonce — attacker-attested "
                f"out-of-sequence nonce (e.g. dst 308 while src still 307) "
                f"slips through "
                f"(cross-chain-destination-accepts-out-of-sequence-inbound-nonce). "
                f"Kelp rsETH $220M exploit 2026-04-18."
            ),
        })
    return hits

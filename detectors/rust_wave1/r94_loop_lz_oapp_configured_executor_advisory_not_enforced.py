"""
r94_loop_lz_oapp_configured_executor_advisory_not_enforced.py

Flags LayerZero OApp lz_receive / execute_message fns that deliver a
cross-chain packet without verifying msg.sender is the OApp's
configured-executor address — any EOA can deliver once verification is
committed, the configured-executor field is advisory only.

Source: Kelp rsETH exploit (banteg gist).
Class: lz-oapp-configured-executor-advisory-not-enforced (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(
    r"(?i)(lz_receive|lzReceive|_lz_receive|_lzReceive|"
    r"execute_message|executeMessage|deliver_message|deliverMessage)"
)
_PACKET_DELIVERY_RE = re.compile(
    r"(commit_verification|commitVerification|"
    r"deliver_payload|deliverPayload|"
    r"inbound\.\s*deliver|endpoint\.\s*lz_?[Rr]eceive|"
    fr"{IDENT}adapter\s*\.\s*lz_?[Rr]eceive)"
)
_EXECUTOR_CHECK_RE = re.compile(
    fr"(require\s*\(\s*msg\.sender\s*==\s*{IDENT}(configured_executor|configuredExecutor|authorized_executor|authorizedExecutor)|"
    fr"assert\w*\s*!?\s*\(\s*{IDENT}(caller|msg\.sender|invoking_address)\s*==\s*{IDENT}configured_executor|"
    r"is_authorized_executor|onlyExecutor|"
    r"require\s*\(\s*executors\s*\[\s*msg\.sender\s*\])"
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
        if not _PACKET_DELIVERY_RE.search(body_nc):
            continue
        if _EXECUTOR_CHECK_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn {name} delivers a cross-chain packet without "
                f"verifying msg.sender is the OApp's configured-executor "
                f"address — any EOA can deliver once verification is "
                f"committed, configured-executor field is advisory only "
                f"(lz-oapp-configured-executor-advisory-not-enforced). "
                f"Source: Kelp rsETH $220M exploit 2026-04-18."
            ),
        })
    return hits

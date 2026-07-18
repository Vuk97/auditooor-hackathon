"""
r94_loop_bridge_destination_adapter_ignores_source_pause_state.py

Flags destination-chain bridge adapter fns that deliver/release tokens
without consulting the source-chain pause state — once the source is
paused (a compromise indicator) the destination still accepts inbound
messages and releases funds.

Source: Kelp rsETH exploit.
Class: bridge-destination-adapter-ignores-source-pause-state (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(
    r"(?i)(lz_receive|lzReceive|_lz_receive|_lzReceive|"
    r"release_tokens_to|credit_to|_credit_to|"
    r"process_incoming|processIncoming)"
)
_DELIVER_RE = re.compile(
    r"(safe_transfer\s*\(|safeTransfer\s*\(|"
    r"token\.transfer\s*\(|underlying\.transfer\s*\(|"
    r"_credit_to\s*\(|creditTo\s*\()"
)
_SRC_PAUSE_CHECK_RE = re.compile(
    r"(is_source_paused|isSourcePaused|"
    r"source_paused\s*\(|sourcePaused\s*\(|"
    fr"assert\w*\s*!?\s*\(\s*!\s*{IDENT}source_pause|"
    fr"require\s*\(\s*!\s*{IDENT}source_paused|"
    r"query_source_pause_state|light_client_source_status|"
    r"check_source_health|crossChainPauseSync|source_pause_oracle)"
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
        if not _DELIVER_RE.search(body_nc):
            continue
        if _SRC_PAUSE_CHECK_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn {name} delivers tokens on the destination chain "
                f"without consulting source-chain pause state — once source "
                f"is paused (compromise indicator) the destination still "
                f"accepts and releases "
                f"(bridge-destination-adapter-ignores-source-pause-state). "
                f"Kelp rsETH $220M exploit."
            ),
        })
    return hits

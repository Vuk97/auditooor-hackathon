"""
r94_loop_layerzero_channel_mismatch.py

Flags LayerZero OApp receive/lz_receive fns that don't validate the
src-endpoint / srcChainId / channel_id against a configured peer mapping.

Class: layerzero-channel-mismatch (both).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)

_FN_NAME_RE = re.compile(r"(?i)(lz_?receive|receive_message|lzreceive|on_receive|oapp_receive)")
_PEER_CHECK_RE = re.compile(
    r"peers?\s*\(|peer_of|trusted_remote|srcChainId\s*==|"
    r"src_chain_id\s*==|channel_id\s*==|assert_peer|verify_peer|"
    r"require!?\s*\([^)]*(srcChainId|peer|channel_id)\s*=="
)


def run(tree, source: bytes, filepath: str):
    hits = []
    root = tree.root_node
    for fn, _impl in functions_in_contractimpl(root, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        if _PEER_CHECK_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` is a LayerZero receive path with no "
                f"src-chain / channel-id / peer equality check. Any LZ "
                f"endpoint can forward a message and have it accepted."
            ),
        })
    return hits

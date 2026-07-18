"""
r94_loop_layerzero_toaddress_oversized_payload_dos.py

Flags OFT / LayerZero sendFrom style fns that pack a caller-supplied
`to_address` / bytes-vector into the outbound LZ payload without
length-capping it — attacker passes a huge address-blob that blows
past the dst-gas budget and bricks the LZ channel.

Source: Solodit #6253 (Sherlock UXD Protocol OFTCore.sendFrom).
Class: layerzero-toaddress-oversized-payload-dos (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(send_from|send|send_oft|oft_send|send_and_call|"
    r"send_tokens|bridge_send|lz_send)"
)
# Packs the to_address into a payload / outbound bytes.
_TO_ADDR_PACK_RE = re.compile(
    r"(?i)(to_address|toAddress|dst_address|dstAddress|"
    r"recipient_bytes|target_bytes)"
)
# Safe: length cap check on the to_address.
_LEN_CAP_RE = re.compile(
    fr"(?i)(to_address\.len\s*\(\s*\)\s*(<=|<)\s*\d+|"
    fr"to_address\.length\s*(<=|<)\s*\d+|"
    fr"require\s*\(\s*{IDENT}to_address\.length\s*(<=|<)|"
    fr"require\s*\(\s*{IDENT}to_address\.len\s*\(\s*\)\s*(<=|<)|"
    fr"assert\w*\s*!?\s*\(\s*{IDENT}to_address\.len\s*\(\s*\)\s*(<=|<)|"
    fr"validate_to_address|validate_address_length|"
    fr"dst_address\.len\s*\(\s*\)\s*(==|<=)\s*\d+|"
    fr"if\s+{IDENT}to_address\.length\s*>\s*\d+\s*\{{\s*revert)"
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
        if not _TO_ADDR_PACK_RE.search(body_nc):
            continue
        if _LEN_CAP_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` packs a caller-supplied "
                f"`to_address` into the outbound LZ payload without a "
                f"length cap — attacker passes a huge address-blob "
                f"that blows past the dst-gas budget and bricks the "
                f"LZ channel "
                f"(layerzero-toaddress-oversized-payload-dos). "
                f"See Solodit #6253 (Sherlock UXD OFTCore.sendFrom)."
            ),
        })
    return hits

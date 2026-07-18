"""
r94_loop_bridge_recipient_non_20_byte_silent_burn.py

Flags bridge `transfer*` / `withdraw_remote*` fns that accept a
variable-length `to` / `recipient` bytes and pass through
`_validate_to_length` (or equivalent) that only checks non-empty /
max-length — not exactly 20 bytes for EVM addresses.

Source: Solodit #64067 (Shieldify Toki Bridge).
Class: bridge-recipient-non-20-byte-silent-burn (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(r"(?i)(transfer_pool|transfer_token|withdraw_remote|bridge_send|transfer_bridge)")
_TO_PARAM_RE = re.compile(
    r"fn\s+\w+\s*\([^)]*\b(to|recipient|dest_addr|target)\s*:\s*(Bytes|BytesN|Vec<u8>|\[u8;\s*\w+\]|bytes|BytesLike)"
)
_LENGTH_VALIDATION_RE = re.compile(
    fr"({IDENT}to\.len\s*\(\s*\)\s*==\s*20|recipient\.len\s*\(\s*\)\s*==\s*20|"
    fr"require\s*\(\s*{IDENT}to\.length\s*==\s*20|"
    fr"assert[!_]?\s*\(\s*{IDENT}to\.len\s*\(\s*\)\s*==\s*20|"
    fr"validate_exactly_20|exactly_20_bytes)"
)
_WEAK_VALIDATION_RE = re.compile(
    fr"(_validate_to_length|validate_length_non_empty|validate_to_min_max|"
    fr"require\s*\(\s*{IDENT}to\.length\s*>\s*0)"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        sig_text = snippet_of(fn, source)
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        if not _TO_PARAM_RE.search(sig_text):
            continue
        if not _WEAK_VALIDATION_RE.search(body_nc + sig_text):
            continue
        if _LENGTH_VALIDATION_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": sig_text[:200],
            "message": (
                f"pub fn `{name}` accepts variable-length recipient "
                f"bytes with only non-empty / max-length validation "
                f"— non-20-byte payload silently truncates on "
                f"destination chain, funds burned (bridge-recipient-"
                f"non-20-byte-silent-burn). See Solodit #64067 "
                f"(Toki Bridge)."
            ),
        })
    return hits

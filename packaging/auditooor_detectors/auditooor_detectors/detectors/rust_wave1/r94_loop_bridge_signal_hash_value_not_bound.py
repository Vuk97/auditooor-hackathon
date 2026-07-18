"""
r94_loop_bridge_signal_hash_value_not_bound.py

Flags bridge signal / message send fns that hash the message header
but OMIT the `value` / `fee` / `amount` fields — processMessage on
the destination trusts header-hash, attacker re-submits same header
with different value.

Source: Solodit #34319 (OpenZeppelin Taiko SignalService).
Class: bridge-signal-hash-value-not-bound (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(send_signal|store_signal|send_message|process_message|commit_message)")
_HASH_BUILD_RE = re.compile(
    r"(keccak256|sha256|hash)\s*\(\s*(abi::encode|&\(|\(|\[)"
)
_VALUE_FIELDS_IN_HASH_RE = re.compile(
    r"(\bvalue\b|\bamount\b|\bfee\b|\bamount_in\b|\bmin_out\b).*\),"
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
        if not _HASH_BUILD_RE.search(body_nc):
            continue
        # Check hash-building line includes value/amount/fee — if NOT, flag
        hash_line_re = re.compile(
            r"(keccak256|sha256|hash)\s*\([^)]{0,500}?\)", re.DOTALL
        )
        flagged = False
        for m in hash_line_re.finditer(body_nc):
            snippet_hash = m.group(0)
            if not re.search(r"\b(value|amount|fee|amount_in|min_out)\b", snippet_hash):
                flagged = True
                break
        if not flagged:
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` builds message-hash without value/"
                f"amount/fee — processMessage trusts header-hash, "
                f"attacker re-submits same header with different "
                f"value (bridge-signal-hash-value-not-bound). "
                f"See Solodit #34319 (Taiko SignalService)."
            ),
        })
    return hits

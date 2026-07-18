"""
r94_loop_hyperlane_ism_bypass.py

Flags Hyperlane message-handling fns that process an inbound message
without calling `verify_ism` / `ism.verify(...)` on the payload. The
ISM (Interchain Security Module) is the mandatory security layer
between mailbox and message handler.

Class: hyperlane-ism-bypass (both).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)

_FN_NAME_RE = re.compile(r"(?i)(handle|process_message|on_message|mailbox_handle)")
_HYPERLANE_CTX_RE = re.compile(r"mailbox|hyperlane|process\s*\(\s*u32|MessageRecipient")
_ISM_VERIFY_RE = re.compile(
    r"ism\.verify|verify_ism|ISM::verify|ism_verify|"
    r"require!?\s*\([^)]*ism\.verify|assert!?\s*\([^)]*ism"
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
        if not _HYPERLANE_CTX_RE.search(body_nc):
            continue
        if _ISM_VERIFY_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` is a Hyperlane message handler that "
                f"does not call `ism.verify(...)` / `verify_ism(...)` "
                f"on the inbound message. Any caller can invoke the "
                f"handler without security verification."
            ),
        })
    return hits

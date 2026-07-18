"""
r94_loop_erc20_transfer_return_unchecked.py

Flags fns that call token.transfer / transferFrom and IGNORE the
returned bool — USDT-style tokens return false instead of reverting,
silent failure credits shares against no tokens.

Source: Solodit #488 (Spartan Protocol).
Class: erc20-transfer-return-unchecked (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(r"(?i)(deposit|withdraw|transfer|harvest|collect|send|swap|borrow|repay)")
_BARE_TRANSFER_RE = re.compile(
    fr"^\s*{IDENT}token\w*\.\s*transfer\s*\(|"
    r"^\s*\w*\.\s*transfer_from\s*\(|"
    r"^\s*\w*\.\s*transferFrom\s*\(",
    re.MULTILINE,
)
_CHECKED_TRANSFER_RE = re.compile(
    fr"safe_transfer|safeTransfer|require\s*\(\s*{IDENT}transfer|"
    fr"\.\s*transfer\s*\([^;]*?\)\s*\.\s*unwrap|"
    fr"assert[!_]?\s*\(\s*{IDENT}transfer|"
    fr"let\s+\w+\s*=\s*{IDENT}transfer\s*\([^;]*\);"
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
        if not _BARE_TRANSFER_RE.search(body_nc):
            continue
        if _CHECKED_TRANSFER_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` calls token.transfer / transferFrom "
                f"without checking the returned bool — USDT-style "
                f"tokens return false instead of reverting, silent "
                f"failure (erc20-transfer-return-unchecked). "
                f"See Solodit #488 (Spartan Protocol)."
            ),
        })
    return hits

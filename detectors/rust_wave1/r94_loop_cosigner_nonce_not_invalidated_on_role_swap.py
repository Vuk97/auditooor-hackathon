"""
r94_loop_cosigner_nonce_not_invalidated_on_role_swap.py

Flags `set_cosigner` / `set_signer` / `rotate_signer` fns that
update a role assignment without also invalidating the old role's
nonce namespace — older signatures under the old role replay.

Source: Solodit #19316 (SigmaPrime Dapper Labs).
Class: cosigner-nonce-not-invalidated-on-role-swap (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(r"(?i)(set_cosigner|set_signer|rotate_signer|reassign_role|change_cosigner)")
_ROLE_UPDATE_RE = re.compile(
    r"(cosigner|signer|primary_signer)\s*=\s*\w+|"
    r"roles\s*\[\s*\w+\s*\]\s*=\s*Role::"
)
_INVALIDATE_RE = re.compile(
    fr"(cosigner_nonce\s*\+\+|cosigner_nonce\s*=\s*0|"
    fr"signer_nonce\s*\+\+|reset_nonce|bump_nonce|invalidate_sigs|"
    fr"nonces\s*\[\s*{IDENT}old_\w+\s*\]\s*=)"
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
        if not _ROLE_UPDATE_RE.search(body_nc):
            continue
        if _INVALIDATE_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` swaps signer/cosigner role without "
                f"bumping the old role's nonce — prior sigs under the "
                f"old role replay after swap (cosigner-nonce-not-"
                f"invalidated-on-role-swap). See Solodit #19316 "
                f"(Dapper Labs)."
            ),
        })
    return hits

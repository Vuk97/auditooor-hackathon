"""
r94_loop_deposit_signer_vs_depositor_mismatch.py

Flags deposit-style Solana fns where token transfer pulls from a
`depositor` token account while the transaction is actually signed
by a DIFFERENT `signer`. Users who approve the program can have their
tokens drained by any signer.

Source: Solodit #56794 (OpenZeppelin SVM Spoke Incremental Audit).
Class: access-control (active promotion from staged stub).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)

_FN_NAME_RE = re.compile(r"(?i)(deposit|deposit_on_behalf|deposit_for)")

_TRANSFER_FROM_RE = re.compile(
    r"token::transfer_from\s*\(|transfer_from_checked\s*\(|"
    r"\.transfer_from\s*\(|spl_token::transfer_from"
)

_DEPOSITOR_PARAM_RE = re.compile(r"\bdepositor\b|\bfrom\b|\bsource_token_account\b")
_SIGNER_PARAM_RE = re.compile(r"\bsigner\b|\bauthority\b|\brequires_signer\b")

_EQUALITY_CHECK_RE = re.compile(
    r"signer\s*==\s*depositor|depositor\s*==\s*signer|"
    r"authority\s*==\s*depositor|depositor\s*==\s*authority|"
    r"require!?\s*\([^)]*signer\s*==\s*\w+\.owner|"
    r"require!?\s*\([^)]*authority\s*==\s*depositor"
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
        # Must take tokens from a depositor and have a separate signer concept
        if not _TRANSFER_FROM_RE.search(body_nc):
            continue
        fn_text = text_of(fn, source)
        if not (_DEPOSITOR_PARAM_RE.search(fn_text) and _SIGNER_PARAM_RE.search(fn_text)):
            continue
        if _EQUALITY_CHECK_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` transfers from `depositor` / `from` while "
                f"accepting a separate `signer` / `authority` arg, but "
                f"does NOT assert the two are equal (or that signer has "
                f"explicit delegation from depositor). Any signer with "
                f"an approved program can drain the depositor's account. "
                f"See Solodit #56794 (SVM Spoke)."
            ),
        })
    return hits

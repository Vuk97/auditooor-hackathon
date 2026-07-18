"""
r94_loop_meta_tx_nonce_not_bumped_on_revert.py

Flags `execute_meta_tx` / `execute_with_sig` fns that wrap an
inner call and re-propagate revert — the nonce increment happens
BEFORE the call but is rolled back on revert, so replay remains
possible.

Source: Solodit #1685 (Code4rena Rolla EIP712MetaTransaction).
Class: meta-tx-nonce-not-bumped-on-revert (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(r"(?i)(execute_meta_tx|execute_with_sig|execute_meta_transaction|exec_meta|relay_meta)")
_INNER_CALL_RE = re.compile(
    r"\.call\s*\(|invoke_contract\s*\(|delegatecall\s*\(|exec_raw\s*\("
)
_POST_SUCCESS_NONCE_RE = re.compile(
    fr"(nonces\s*\[\s*\w+\s*\]\s*\+=|nonce\s*\.\s*insert\s*\(|"
    fr"if\s+{IDENT}success\s*\{{[\s\S]{{0,100}}?nonces\s*\[|"
    fr"after_call_nonce_bump|commit_nonce)"
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
        if not _INNER_CALL_RE.search(body_nc):
            continue
        if _POST_SUCCESS_NONCE_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` wraps inner call without a "
                f"post-success nonce-bump pattern — if inner call "
                f"reverts, whole tx reverts and nonce stays "
                f"unchanged, sig replayable (meta-tx-nonce-not-"
                f"bumped-on-revert). See Solodit #1685 (Rolla)."
            ),
        })
    return hits

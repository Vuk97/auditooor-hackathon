"""
r94_loop_cross_chain_borrow_no_interest_accrual_on_subsequent.py

Flags cross-chain borrow handler fns that INCREMENT the existing
principal (`borrow_amount += new_amount`) without first accruing
interest on the pre-existing balance — second borrow of same asset
gets interest-free extension of prior principal.

Source: Solodit #58397 (Sherlock LEND).
Class: cross-chain-borrow-no-interest-accrual-on-subsequent (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(
    r"(?i)(handle_borrow|process_borrow|cross_chain_borrow|"
    r"on_borrow|borrow_ccm|borrow_xchain|handle_ccip_borrow)"
)
_INCREMENT_PRINCIPAL_RE = re.compile(
    r"(borrow_amount|principal|debt)\s*\[\s*\w+\s*\]\s*\+=|"
    r"self\.(borrow_amount|principal|debt)\s*\+=|"
    r"borrow_amount\s*=\s*borrow_amount\s*\+"
)
_ACCRUE_CALL_RE = re.compile(
    r"(accrue_interest|update_interest|_accrue|compound_interest|"
    r"accrue_before_mutation|_refresh_interest)\s*\("
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
        if not _INCREMENT_PRINCIPAL_RE.search(body_nc):
            continue
        if _ACCRUE_CALL_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` increments borrow principal without "
                f"calling accrue_interest first — subsequent borrow "
                f"of same asset gets interest-free extension "
                f"(cross-chain-borrow-no-interest-accrual-on-"
                f"subsequent). See Solodit #58397 (LEND)."
            ),
        })
    return hits

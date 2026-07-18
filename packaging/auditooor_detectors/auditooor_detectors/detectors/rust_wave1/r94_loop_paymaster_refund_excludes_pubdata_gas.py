"""
r94_loop_paymaster_refund_excludes_pubdata_gas.py

Flags paymaster refund / postTransaction fns that compute the
refund amount from `_maxRefundedGas` (or equivalent gas counter)
without subtracting `spentOnPubdata` / `pubdata_gas` — paymaster
over-refunds the user, drain vector.

Source: Solodit #33188 (Code4rena zkSync).
Class: paymaster-refund-excludes-pubdata-gas (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(
    r"(?i)(post_transaction|post_op|postOp|"
    r"refund_gas|refund_user|compute_refund|"
    r"finalize_transaction|post_paymaster)"
)
# Must see a refund / credit / transfer operation.
_REFUND_RE = re.compile(
    r"(?i)(refund|credit\w*\s*\(|\bpay_refund|transfer\s*\(\s*\w*(user|sender|from)|"
    r"_max_refunded_gas|max_refunded_gas|refunded_gas)"
)
_PUBDATA_RE = re.compile(
    r"(?i)(spent_?on_?pubdata|pubdata_gas|pubdata_spent|"
    r"spent_pubdata|pubdata_price|pubdata_cost)"
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
        if not _REFUND_RE.search(body_nc):
            continue
        if _PUBDATA_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` refunds gas to user without "
                f"subtracting spent_on_pubdata / pubdata_gas — "
                f"paymaster over-refunds, drain vector "
                f"(paymaster-refund-excludes-pubdata-gas). "
                f"See Solodit #33188 (Code4rena zkSync)."
            ),
        })
    return hits

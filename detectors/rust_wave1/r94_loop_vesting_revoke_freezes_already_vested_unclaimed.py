"""
r94_loop_vesting_revoke_freezes_already_vested_unclaimed.py

Flags vesting-revoke fns that zero out a grant WITHOUT first paying out
the already-vested-but-unclaimed portion to the beneficiary — revoking
freezes tokens the beneficiary had already earned.

Source: Solodit #59721 (Quantstamp TokenOps TokenVesting).
Class: vesting-revoke-freezes-already-vested-unclaimed (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(
    r"(?i)(revoke_grant|revokeGrant|revoke_vesting|revokeVesting|"
    r"cancel_grant|cancelGrant|terminate_vesting|terminateVesting|"
    r"admin_revoke|adminRevoke)"
)
_ZEROS_RE = re.compile(
    r"(grant\s*\.\s*(total_amount|totalAmount|allocated|remaining)\s*=\s*0|"
    r"grants\s*\[\s*\w+\s*\]\s*=\s*default\s*\(\s*\)|"
    r"grants\s*\.\s*remove\s*\(|"
    r"delete\s+grants|"
    r"grant\s*\.\s*revoked\s*=\s*true)"
)
_PAYOUT_VESTED_RE = re.compile(
    r"(send_vested_to_beneficiary|sendVestedToBeneficiary|"
    r"pay_already_vested|payAlreadyVested|"
    fr"transfer\s*\(\s*{IDENT}beneficiary\s*,\s*{IDENT}(already_vested|vested_amount|released_but_not_claimed)|"
    r"settle_vested_before_revoke|settleBeforeRevoke|"
    r"final_payout|finalPayout)"
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
        if not _ZEROS_RE.search(body_nc):
            continue
        if _PAYOUT_VESTED_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` revokes a vesting grant by zeroing it "
                f"WITHOUT first paying out the already-vested-but-unclaimed "
                f"portion — beneficiary loses what they had earned "
                f"(vesting-revoke-freezes-already-vested-unclaimed). "
                f"See Solodit #59721 (Quantstamp TokenOps TokenVesting)."
            ),
        })
    return hits

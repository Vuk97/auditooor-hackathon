"""
r94_loop_restaking_node_operator_withdraw_credentials_overwrite.py

Flags stake / delegate / register_validator fns that call
`setWithdrawCredentials` / store validator withdrawal credentials
on behalf of the node operator without an invariant check that the
current credentials are EITHER zero OR the LRT vault's own address.
Malicious node operator overwrites credentials to their own wallet,
stealing ETH on eventual withdrawal.

Source: Solodit #30472 (MixBytes KelpDAO NodeDelegator).
Class: restaking-node-operator-withdraw-credentials-overwrite (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(stake|stake_on_beacon|stake_eth|deposit_stake|"
    r"register_validator|delegate_to_operator|add_validator|"
    r"set_withdrawal_credentials|configure_credentials)"
)
# Touches the withdraw-credentials state.
_CREDS_RE = re.compile(
    r"(?i)(withdraw_credentials|withdrawal_credentials|"
    r"set_withdraw_credentials|set_withdrawal_credentials|"
    r"withdrawCredentials|withdrawalCredentials)"
)
# Safe: check existing value is zero or the vault's own address, OR authorize via access control.
_GUARD_RE = re.compile(
    fr"(?i)(current_?creds\s*==\s*\[\s*0|"
    fr"current_?creds\s*\.\s*is_zero|"
    fr"current_?creds\s*==\s*{IDENT}self_?address|"
    fr"assert\w*\s*!?\s*\(\s*{IDENT}creds\s*==\s*\[\s*0|"
    fr"require\s*\(\s*{IDENT}creds\s*==\s*address\(0\)|"
    fr"require\s*\(\s*{IDENT}creds\s*==\s*{IDENT}vault|"
    fr"only_owner|only_admin|require_auth\s*\(\s*owner|"
    fr"require_auth\s*\(\s*&?\s*admin|require_auth\s*\(\s*&?\s*vault)"
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
        if not _CREDS_RE.search(body_nc):
            continue
        if _GUARD_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` writes/overwrites validator "
                f"withdraw_credentials without asserting the existing "
                f"slot is zero / vault-owned, and without an admin-"
                f"only auth guard — malicious node operator overwrites "
                f"credentials to their own wallet, stealing ETH "
                f"(restaking-node-operator-withdraw-credentials-overwrite). "
                f"See Solodit #30472 (MixBytes KelpDAO)."
            ),
        })
    return hits

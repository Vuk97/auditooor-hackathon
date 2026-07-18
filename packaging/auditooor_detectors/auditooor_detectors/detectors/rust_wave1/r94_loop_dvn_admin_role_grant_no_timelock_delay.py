"""
r94_loop_dvn_admin_role_grant_no_timelock_delay.py

Flags admin-role-granting fns that instantly assign a role-bearing
capability (has_role[x] = true, _grant_role(...), admins.insert(...))
without any timelock, pending_admin queue, or two-step accept flow —
a compromised current admin can propagate capability in a single tx.

Source: Kelp rsETH exploit (banteg gist).
Class: dvn-admin-role-grant-no-timelock-delay (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(
    r"(?i)(grant_role|grantRole|add_admin|addAdmin|"
    r"set_admin|setAdmin|add_signer|addSigner|"
    r"transfer_ownership|transferOwnership|delegate_admin_role)"
)
_INSTANT_GRANT_RE = re.compile(
    fr"(has_role\s*\[\s*\w+\s*\]\s*=\s*true|"
    r"_grant_role\s*\(|"
    fr"roles\s*\[\s*{IDENT}ADMIN_ROLE\s*\]\s*=|"
    r"admins\.insert|"
    r"role_members\.insert|"
    fr"_roles\s*\[\s*{IDENT}role\s*\]\.members\s*\[\s*\w+\s*\]\s*=\s*true)"
)
_TIMELOCK_RE = re.compile(
    fr"(timelock|TimeLock|TIMELOCK|"
    r"pending_admin|pendingAdmin|"
    r"scheduled_role|scheduledRole|"
    r"queue_admin_grant|queueAdminGrant|"
    r"two_step_transfer|twoStepTransfer|"
    r"accept_admin|acceptAdmin|"
    fr"delay\s*:\s*{IDENT}GRANT_DELAY|"
    fr"require\s*\(\s*{IDENT}block\.timestamp\s*>=\s*{IDENT}(scheduled|pending_admin_granted_at|ready_at))"
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
        if not _INSTANT_GRANT_RE.search(body_nc):
            continue
        if _TIMELOCK_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` grants an admin role / role-bearing "
                f"capability instantly without timelock / two-step "
                f"confirmation — a compromised current admin can "
                f"propagate capability in a single tx "
                f"(dvn-admin-role-grant-no-timelock-delay). "
                f"Kelp DVN admin granted ADMIN_ROLE to 10 new EOAs "
                f"10 days pre-exploit."
            ),
        })
    return hits

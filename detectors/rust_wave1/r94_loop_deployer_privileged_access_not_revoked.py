"""
r94_loop_deployer_privileged_access_not_revoked.py

Flags constructors / `new` / `initialize` fns that grant
DEFAULT_ADMIN_ROLE (or similar) to the deployer / msg_sender
WITHOUT a follow-up revoke or role-transfer mechanism in the
source.

Source: Solodit #21313 (ConsenSys Lybra GovernanceTimelock).
Class: deployer-privileged-access-not-revoked (both).
"""

from __future__ import annotations
import re
from _util import source_nocomment

_GRANT_IN_CTOR_RE = re.compile(
    r"(constructor|fn\s+new|fn\s+initialize)\s*\([^{]{0,200}\{[^}]{0,600}?"
    r"(grant_role|grantRole|_grant_role|setup_role|_setupRole|set_admin)\s*\([^)]*"
    r"(DEFAULT_ADMIN_ROLE|ADMIN_ROLE|Role::Admin)[^)]*\)[\s\S]{0,200}?"
    r"(msg_sender|env\.invoker|_msgSender|msg\.sender|deployer)",
    re.DOTALL,
)
_REVOKE_RE = re.compile(
    r"(revoke_role|revokeRole|_revoke_role|renounce_role|renounceRole|transfer_admin_role)"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    src = source_nocomment(source)
    m = _GRANT_IN_CTOR_RE.search(src)
    if not m:
        return hits
    if _REVOKE_RE.search(src):
        return hits
    line = src.count("\n", 0, m.start()) + 1
    hits.append({
        "severity": "high",
        "line": line,
        "col": 0,
        "snippet": src[m.start():m.start()+200],
        "message": (
            "Constructor grants DEFAULT_ADMIN_ROLE to deployer but no "
            "revoke/renounce/transfer-admin is present in source — "
            "deployer retains unilateral privileges (deployer-"
            "privileged-access-not-revoked). See Solodit #21313 "
            "(Lybra GovernanceTimelock)."
        ),
    })
    return hits

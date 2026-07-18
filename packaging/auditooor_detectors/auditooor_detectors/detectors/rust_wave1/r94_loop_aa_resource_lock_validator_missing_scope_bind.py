"""
r94_loop_aa_resource_lock_validator_missing_scope_bind.py

Flags resource-lock / session-key validators that call
validateUserOp-style authorization but do NOT bind the locked
resource (token address, recipient, method selector, spend cap) to
the target call-data in the userOp. Attacker crafts a userOp whose
call-data moves value outside the locked scope, draining the wallet.

Source: Solodit #61410 (Shieldify Etherspot CredibleAccountModule
ResourceLockValidator).
Class: aa-resource-lock-validator-missing-scope-bind (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(validate_user_op|validateUserOp|"
    r"validate_session|validate_lock|"
    r"verify_resource_lock|check_session_permission)"
)
# Must reference a resource lock / session key / scope.
_LOCK_RE = re.compile(
    r"(resource_?lock|Resource_?Lock|ResourceLock|"
    r"session_?key|Session_?Key|SessionKey|"
    r"session_?permission|SessionPermission|"
    r"locked_token|LockedToken|"
    r"lock_scope|LockScope|"
    r"session_scope|SessionScope|"
    r"permission_scope|PermissionScope)"
)
# Safe: binds call-data selector / target / recipient / amount to the lock.
_SCOPE_BIND_RE = re.compile(
    fr"(?i)(lock\.target\s*==|lock\.selector\s*==|lock\.recipient\s*==|"
    fr"lock\.token\s*==|lock\.amount\s*>=|lock\.amount\s*<=|"
    fr"scope\.target\s*==|scope\.selector\s*==|"
    fr"{IDENT}selector\s*==\s*{IDENT}lock\.|{IDENT}target\s*==\s*{IDENT}lock\.|"
    fr"calldata\[0\s*\.\s*\.\s*4\]\s*==|call_data\[0\s*\.\s*\.\s*4\]\s*==)"
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
        if not _LOCK_RE.search(body_nc):
            continue
        if _SCOPE_BIND_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` references a resource_lock / "
                f"session_key scope but does not bind the locked "
                f"target / selector / recipient / amount to the "
                f"userOp's call-data — attacker crafts a userOp "
                f"moving value outside the locked scope "
                f"(aa-resource-lock-validator-missing-scope-bind). "
                f"See Solodit #61410 (Shieldify Etherspot)."
            ),
        })
    return hits

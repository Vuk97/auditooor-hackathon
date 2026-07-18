"""
r94_admin_self_grant_role.py

Flags admin-management fns where a *user-supplied* caller ends up being
written as the new admin / governance / owner without any cross-check
against the prior admin or a multisig, i.e. the privileged role is
granted to the very address that invoked the function.

Maps to Solidity:
  - admin-self-grant-privileged-role
  - self-admin-grant-privilege-escalation
  - admin-rescue-drain-no-whitelist (narrower variant)

Heuristic:
  - fn name matches one of `grant_role`, `grant_admin`, `set_admin`,
    `transfer_admin`, `set_owner`, `transfer_ownership`, `set_governance`,
    `assume_admin`, `take_ownership`, `become_admin`.
  - Body writes to an admin-ish storage key (`admin`, `owner`,
    `governance`, `ADMIN`, etc.).
  - Body writes either `caller` (`env.invoker()` / fn param named `caller`
    / `env.current_contract_address()` passthrough) AS the new value.
  - Body does NOT call `.require_auth()` on the *prior* admin (matched by
    a `storage().get(&Key::Admin)` read followed by `.require_auth()`).
"""

from __future__ import annotations

import re

from _util import (
    functions_in_contractimpl, fn_body, fn_name, is_pub, text_of,
    walk_no_nested_fn, line_col, snippet_of,
)


_ADMIN_FN_RE = re.compile(
    r"^(grant_role|grant_admin|set_admin|transfer_admin|set_owner|"
    r"transfer_ownership|set_governance|assume_admin|take_ownership|"
    r"become_admin|claim_admin|set_operator)$"
)

_ADMIN_KEY_TOKENS = ("Admin", "ADMIN", "admin", "Owner", "OWNER", "owner",
                     "Governance", "GOVERNANCE", "governance",
                     "Operator", "OPERATOR", "operator")

# "self-grant" signals in the body
_SELF_TOKENS = (
    "caller", "Caller",
    "env.invoker()", ".invoker()",
    "current_contract_address",
    "msg_sender", "msg.sender",
)


def _has_require_auth(body_text: str) -> bool:
    return ".require_auth(" in body_text


def run(tree, source: bytes, filepath: str):
    hits = []
    root = tree.root_node
    for fn, _impl in functions_in_contractimpl(root, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        if not _ADMIN_FN_RE.match(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_text = text_of(body, source)

        # Writes to admin-ish key?
        has_admin_key = any(tok in body_text for tok in _ADMIN_KEY_TOKENS)
        if not has_admin_key:
            continue
        if not re.search(r"\.set\s*\(", body_text):
            continue

        # Body references a "caller/self" identifier (possible self-grant)
        has_self = any(tok in body_text for tok in _SELF_TOKENS)
        # Prior-admin auth check present?
        if _has_require_auth(body_text):
            # Still flag if the only require_auth is on the *new* address
            # — heuristically, require the current admin be loaded. Look
            # for `.get(&...Admin)` or `.get(&Key::Admin)` etc.
            if re.search(r"\.get\s*\([^)]*(Admin|Owner|Governance|Operator)",
                         body_text):
                # The fn reads the current admin AND calls require_auth —
                # treat as safe.
                continue

        # Flag cases where the fn neither loads prior admin nor gates on
        # require_auth. (Self-grant is the strongest subclass; even
        # without self-grant, unguarded admin rotation is High.)
        line, col = line_col(fn)
        severity = "high" if has_self else "med"
        extra = (" — new admin appears to be the caller (self-grant)"
                 if has_self else "")
        hits.append({
            "severity": severity,
            "line": line,
            "col": col,
            "snippet": snippet_of(body, source, 200),
            "message": (
                f"pub fn `{name}` writes an admin/owner/governance key "
                f"without loading the current admin and gating on "
                f"`.require_auth()`{extra}."
            ),
        })
    return hits

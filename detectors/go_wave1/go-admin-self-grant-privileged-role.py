"""
go-admin-self-grant-privileged-role.py

Flags Go admin/role setters that write the caller back into a privileged slot
without an auth guard or a self-proposal rejection.

Confirmed corpus anchors:
  - reference/patterns.dsl/admin-self-grant-privileged-role.yaml
  - reference/patterns.dsl/admin-bypass-umbrella.yaml
  - reference/patterns.dsl/two-step-admin-propose-self-removes-role-on-accept.yaml

This detector is intentionally narrow. It only fires when a public/exported
function:
  1. Looks like a grant / transfer / propose / accept admin setter.
  2. Mutates an admin/owner/role/governance field or calls a role-grant helper.
  3. Writes a caller/self token into that privileged slot.
  4. Lacks an access-control guard or an explicit self-proposal rejection.
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.go-admin-self-grant-privileged-role"

_PRIV_FN_RE = re.compile(
    r"(?i)^(GrantRole|GrantAdmin|SetAdmin|TransferAdmin|SetOwner|"
    r"TransferOwnership|SetGovernance|BecomeAdmin|ClaimAdmin|"
    r"ProposeAdmin|AcceptAdmin|NominateAdmin|NominateOwner)$"
)

_PRIV_SLOT_RE = re.compile(
    r"(?i)\b(admin|owner|governance|operator|manager|keeper|minter|"
    r"pauser|upgrader|role)\w*\b"
)

_CALLER_TOKEN_RE = re.compile(
    r"(?i)\b(caller|msg\.Sender|msg\.Creator|msg\.Authority|req\.Sender|"
    r"request\.Sender|ctx\.Sender|tx\.Sender|msg\.Caller|msg\.Owner|"
    r"msg\.Admin|msg\.Role|self)\b"
)

_SELF_WRITE_RE = re.compile(
    r"(?i)(?:"
    r"\b(?:admin|owner|governance|operator|manager|keeper|minter|pauser|"
    r"upgrader|role)\w*\b\s*=\s*(?:caller|msg\.Sender|msg\.Creator|"
    r"msg\.Authority|req\.Sender|request\.Sender|ctx\.Sender|tx\.Sender|"
    r"msg\.Caller|msg\.Owner|msg\.Admin|msg\.Role|self)\b"
    r"|(?:grantRole|GrantRole|grantAdmin|GrantAdmin|_grantRole|_setupRole|"
    r"setAdmin|SetAdmin|setOwner|SetOwner|transferOwnership|TransferOwnership|"
    r"proposeAdmin|ProposeAdmin|acceptAdmin|AcceptAdmin)\s*\([^)]*"
    r"(?:caller|msg\.Sender|msg\.Creator|msg\.Authority|req\.Sender|"
    r"request\.Sender|ctx\.Sender|tx\.Sender|msg\.Caller|msg\.Owner|"
    r"msg\.Admin|msg\.Role|self)\b"
    r")"
)

_AUTH_GUARD_RE = re.compile(
    r"(?i)(onlyOwner|onlyAdmin|onlyRole|onlyGovernance|onlyManager|"
    r"onlyOperator|onlyKeeper|onlyPauser|onlyUpgrader|requiresAuth|"
    r"requireAuth|RequireAuth|hasRole|_checkRole|CheckAuthority|"
    r"EnsureAuthority|AssertAuthority|newAdmin\s*!=\s*(?:caller|msg\.Sender|"
    r"msg\.Creator|msg\.Authority|req\.Sender|request\.Sender|ctx\.Sender|"
    r"tx\.Sender|msg\.Caller|msg\.Owner|msg\.Admin|msg\.Role|self)|newOwner\s*!=\s*(?:caller|msg\.Sender|msg\.Creator|"
    r"msg\.Authority|req\.Sender|request\.Sender|ctx\.Sender|tx\.Sender|"
    r"msg\.Caller|msg\.Owner|msg\.Admin|msg\.Role|self)|(?:caller|msg\.Sender|msg\.Creator|msg\.Authority|req\.Sender|"
    r"request\.Sender|ctx\.Sender|tx\.Sender|msg\.Caller|msg\.Owner|"
    r"msg\.Admin|msg\.Role|self)\s*(?:!=|==)\s*"
    r"(?:k\.(?:admin|owner|governance|operator|manager|keeper|minter|pauser|"
    r"upgrader)|(?:admin|owner|governance|operator|manager|keeper|minter|"
    r"pauser|upgrader)\b)|cannot self-propose|SELF_PROPOSE|reject self)"
)


def run(engine, filepath: str):
    hits = []
    for fn in engine.functions():
        name = engine.fn_name(fn)
        if not name or name == "?":
            continue
        if not _PRIV_FN_RE.match(name):
            continue

        body = engine.fn_body(fn)
        if body is None:
            continue

        body_text = engine.text(body)
        fn_text = engine.text(fn)
        if not _PRIV_SLOT_RE.search(body_text):
            continue
        if not _CALLER_TOKEN_RE.search(body_text):
            continue
        if not _SELF_WRITE_RE.search(body_text):
            continue
        if _AUTH_GUARD_RE.search(body_text):
            continue

        hits.append({
            "severity": "high",
            "line": engine.line(fn),
            "col": engine.col(fn),
            "snippet": fn_text.splitlines()[0][:160],
            "message": (
                f"`{name}` writes a caller/self token into privileged "
                f"admin/role state without an auth guard or a self-proposal "
                f"rejection. A public grant / transfer / propose path should "
                f"not let the caller self-grant privileged control. "
                f"(class: admin-bypass)"
            ),
        })

    return hits

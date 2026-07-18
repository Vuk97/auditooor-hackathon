"""
cosmos_msgserver_missing_authority_check.py

Detects missing authority validation on cosmos-sdk msgServer handlers that
perform privileged state mutation.

A cosmos-sdk `Msg` handler that mutates governance/admin-gated state (params,
fees, allowlists, module config) MUST verify the caller's authority against
the module's expected gov/authority address before mutating, typically via:
  - `if msg.Authority != k.GetAuthority() { return ErrUnauthorized }`, OR
  - `k.authority` comparison / `authtypes.NewModuleAddress(govtypes.ModuleName)`,
    OR
  - an `EnsureAuthority` / `assertAuthority` / `checkAuthority` helper call.

When a handler reads `msg.GetAuthority()` / `msg.Authority` (or names a
privileged action like `UpdateParams`) but never compares it to the module
authority, ANY account can broadcast the Msg and mutate admin-only state.

Bug class: HIGH (permissionless privileged-state mutation -> config takeover).
Platform:  cosmos-sdk app-chains (dYdX, Osmosis, Sei, Spark coordinator).
Empirical anchor: dydx-cantina-192 (Go HIGH - permissionless msgServer route).
Cross-lang sibling: rust_wave1.anchor_owner_check_missing_on_authority.

Algorithm (engine-first, language-neutral helpers + regex on body text):
1. Iterate every Go function/method.
2. Keep only msgServer-shaped handlers: receiver/name looks like a Msg
   handler (`func (k msgServer) UpdateX(...)` / name in privileged set, or
   the body references `msg.Authority` / `msg.GetAuthority()`).
3. If the body never compares authority to a module-authority source
   (GetAuthority / k.authority / NewModuleAddress / an authority-assert
   helper) -> flag.
4. Handlers whose name is clearly non-privileged and that never touch an
   authority field are skipped (avoids flagging ordinary user Msgs).
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.cosmos_msgserver_missing_authority_check"

# Privileged handler-name verbs: presence strongly implies admin-gated state.
_PRIVILEGED_NAME_RE = re.compile(
    r"^(Update|Set|Add|Remove|Delete|Upsert|Configure|Register|Enable|"
    r"Disable|Grant|Revoke|Pause|Unpause|Init)"
    r"(Params|Fee|Fees|Config|Authority|Admin|Allow|Allowlist|Whitelist|"
    r"Module|Market|Asset|Oracle|Pair|Rate|Limit|Cap)",
)

# The handler reads the caller-supplied authority field.
_READS_AUTHORITY_RE = re.compile(
    r"\bmsg\.(GetAuthority\s*\(\s*\)|Authority)\b"
)

_MSGSERVER_RECEIVER_RE = re.compile(r"\b(msgServer|MsgServer)\b")

# Any of these proves the handler validates authority -> safe.
# NOTE: a bare `msg.GetAuthority()` is a READ of the caller-supplied field,
# NOT a check; the keeper-side `k.GetAuthority()` (or `<recv>.GetAuthority`)
# is the module-authority source, so the safe pattern excludes `msg.`.
_AUTHORITY_CHECK_RE = re.compile(
    r"((?<!msg)(?<!Msg)\.GetAuthority\s*\(\s*\)"  # k.GetAuthority(), not msg.
    r"|\bk\.authority\b"                    # stored authority field
    r"|NewModuleAddress\s*\("               # authtypes.NewModuleAddress(gov)
    r"|\b(Ensure|Assert|Check|Validate|Require)Authority\b"  # helper
    r"|\bauthorities\s*\["                  # allowlist map lookup
    r"|\bgovtypes\.ModuleName\b)"
)

# Names that are clearly user-facing (not admin) -> skip unless they still
# read an authority field (which would itself be suspicious).
_USER_FACING_RE = re.compile(
    r"^(Send|Transfer|Deposit|Withdraw|Claim|Swap|PlaceOrder|CancelOrder|"
    r"Mint|Burn|Vote|Delegate|Undelegate|Stake|Unstake)"
)


def _is_msgserver_handler(name: str, header_text: str, body_text: str) -> bool:
    """A Go fn is a cosmos Msg handler when it is in the MsgServer receiver
    surface or when it directly reads a caller-supplied authority field."""
    if _PRIVILEGED_NAME_RE.match(name) and _MSGSERVER_RECEIVER_RE.search(header_text):
        return True
    if _READS_AUTHORITY_RE.search(body_text):
        return True
    return False


def run(engine, filepath: str):
    hits = []
    for fn in engine.functions():
        name = engine.fn_name(fn)
        if not name or name == "?":
            continue
        body = engine.fn_body(fn)
        if body is None:
            continue
        body_text = engine.text(body)
        header_text = engine.text(fn).splitlines()[0]

        if not _is_msgserver_handler(name, header_text, body_text):
            continue

        # Skip plainly user-facing handlers that do not touch authority.
        if (_USER_FACING_RE.match(name)
                and not _READS_AUTHORITY_RE.search(body_text)):
            continue

        # Safe if the body validates authority against a module source.
        if _AUTHORITY_CHECK_RE.search(body_text):
            continue

        reads_auth = bool(_READS_AUTHORITY_RE.search(body_text))
        why = ("reads `msg.Authority` but never compares it to the module "
               "authority"
               if reads_auth
               else "is a privileged-named handler with no authority check")
        hits.append({
            "severity": "high",
            "line": engine.line(fn),
            "col": engine.col(fn),
            "snippet": engine.text(fn).splitlines()[0][:160],
            "message": (
                f"cosmos-sdk msgServer handler `{name}` {why}. "
                f"Any account can broadcast this Msg and mutate admin-gated "
                f"state. Compare against k.GetAuthority() / module address "
                f"before mutation. (anchor: dydx-cantina-192)"),
        })
    return hits

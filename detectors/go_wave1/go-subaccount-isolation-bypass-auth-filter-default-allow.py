"""
go-subaccount-isolation-bypass-auth-filter-default-allow.py

Sibling Go/Cosmos detector for the same sub-account-isolation-bypass class as
the W68 missing-owner-check seed, but on the authenticator side.

It catches subaccount-filter authenticators that:
1. inspect `request.Msg` via a type switch,
2. collect or validate only a subset of subaccount-bearing message types, and
3. default-allow every unhandled message with `return nil`.

That shape is dangerous because later-added or sibling message types that carry
subaccount identifiers can bypass the whitelist entirely. The canonical anchor
is dYdX AccountPlus `SubaccountFilter.Authenticate`, which whitelists selected
clob messages but default-allows x/sending messages like transfer/withdraw.
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.go-subaccount-isolation-bypass-auth-filter-default-allow"

_AUTH_FILTER_FN_RE = re.compile(r"^(Authenticate|Validate|Check)[A-Za-z0-9_]*$")
_SUBACCOUNT_FILTER_RE = re.compile(
    r"(SubaccountFilter|ErrSubaccountVerification|whitelist|requestSubaccountNums|SubaccountId\.Number)"
)
_REQUEST_SWITCH_RE = re.compile(
    r"(switch\s+msg\s*:=\s*request\.Msg\.\(type\)\s*\{|switch\s+request\.Msg\.\(type\)\s*\{)"
)
_DEFAULT_ALLOW_RE = re.compile(
    r"default:\s*(?://[^\n]*\n\s*)*(?:[A-Za-z_][\w]*\s*=\s*[A-Za-z_][\w]*\s*\n\s*)*return\s+nil\b",
    re.S,
)
_HANDLED_SUBACCOUNT_MSG_RE = re.compile(
    r"(MsgPlaceOrder|MsgCancelOrder|MsgBatchCancel|SubaccountId\.Number)"
)
_SAFE_COVERAGE_RE = re.compile(
    r"(MsgCreateTransfer|MsgWithdrawFromSubaccount|MsgDepositToSubaccount|ErrSubaccountVerification)"
)


def run(engine, filepath: str):
    hits = []
    for fn in engine.functions():
        name = engine.fn_name(fn)
        if not name or name == "?":
            continue
        if not _AUTH_FILTER_FN_RE.search(name):
            continue
        body = engine.fn_body(fn)
        if body is None:
            continue
        body_text = engine.text(body)

        if not _SUBACCOUNT_FILTER_RE.search(body_text):
            continue
        if not _REQUEST_SWITCH_RE.search(body_text):
            continue
        if not _DEFAULT_ALLOW_RE.search(body_text):
            continue
        if not _HANDLED_SUBACCOUNT_MSG_RE.search(body_text):
            continue
        if _SAFE_COVERAGE_RE.search(body_text) and "default:" not in body_text:
            continue

        hits.append({
            "severity": "high",
            "line": engine.line(fn),
            "col": engine.col(fn),
            "snippet": engine.text(fn).splitlines()[0][:160],
            "message": (
                f"`{name}` looks like a subaccount whitelist authenticator "
                f"that type-switches on `request.Msg` and default-allows "
                f"unhandled message types. New or sibling subaccount-bearing "
                f"Msgs can bypass the isolation filter unless the switch "
                f"fails closed. (class: sub-account-isolation-bypass)"
            ),
        })
    return hits

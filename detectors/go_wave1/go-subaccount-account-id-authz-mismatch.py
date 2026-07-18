"""
go-subaccount-account-id-authz-mismatch.py

Sibling Go/Cosmos detector for sub-account-isolation-bypass.

The class invariant is broader than one dYdX literal: a handler or
authenticator must bind the signer, sender, owner, or explicit delegated
authority to every affected subaccount or account id before it allows the
request or mutates balances/state for that id.

This detector catches two same-class shapes:
1. A subaccount authenticator type-switches on request.Msg and default-allows
   unknown message types.
2. A keeper or MsgServer reads, writes, transfers, withdraws, or settles a
   caller-supplied subaccount/account id without an owner/authz check.

It is recall-oriented and intentionally reports the function containing the
missing binding. Runnable PoCs and target-specific source review are still
required before any finding posture.
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.go-subaccount-account-id-authz-mismatch"

_AUTHISH_NAME_RE = re.compile(
    r"(Authenticate|Authorize|Validate|Check|Can[A-Z]|Allowed|Filter)"
)

_HANDLER_NAME_RE = re.compile(
    r"(Withdraw|Transfer|Send|Settle|Claim|Cancel|Place|Deposit|Update|"
    r"Create|Delete|Move|Liquidate|Close|Release|Refund|Handle|MsgServer)"
)

_SUBACCOUNT_RE = re.compile(
    r"(Subaccount|SubAccount|SubaccountID|SubaccountId|SubaccountIds|"
    r"AccountID|AccountId|AccountNumber|accountID|accountId|subaccount)"
)

_CALLER_SUPPLIED_ID_RE = re.compile(
    r"(msg\.[A-Za-z0-9_]*(?:Subaccount|SubAccount|AccountId|AccountID)"
    r"|request\.Msg"
    r"|GetMsgs\s*\(\s*\)"
    r"|SubaccountId"
    r"|SubaccountID)"
)

_REQUEST_SWITCH_RE = re.compile(
    r"(switch\s+msg\s*:=\s*request\.Msg\.\(type\)\s*\{"
    r"|switch\s+request\.Msg\.\(type\)\s*\{)"
)

_DEFAULT_ALLOW_RE = re.compile(
    r"default:\s*(?://[^\n]*\n\s*)*"
    r"(?:[A-Za-z_][\w]*\s*=\s*[A-Za-z_][\w]*\s*\n\s*)*"
    r"return\s+nil\b",
    re.S,
)

_FAIL_CLOSED_RE = re.compile(
    r"default:\s*(?://[^\n]*\n\s*)*return\s+"
    r"(?:[^;\n]*Err|fmt\.Errorf|errors\.New|status\.Error|sdkerrors\.)",
    re.S,
)

_SUBACCOUNT_MUTATION_RE = re.compile(
    r"(SendCoins|SendCoinsFromModuleToAccount|SendCoinsFromAccountToModule|"
    r"BankKeeper|bankKeeper|Transfer|Withdraw|Deposit|Settle|Claim|Refund|"
    r"Move|UpdateSubaccount|SetSubaccount|MustGetSubaccount|GetSubaccount|"
    r"LoadSubaccount|SubaccountKeeper|SetAccount|GetAccount|SetBalance|"
    r"AddCoins|SubCoins|Debit|Credit)"
)

_AUTHZ_BINDING_RE = re.compile(
    r"(CheckValidSubaccount|ValidateSubaccount|ValidateSubaccountId|"
    r"ValidateSubaccountID|AuthorizeSubaccount|IsAuthorized|HasPermission|"
    r"HasAuthorization|OwnsSubaccount|CanUseSubaccount|CheckSubaccountOwner|"
    r"CheckOwner|VerifyOwner|RequireOwner|AssertOwner|authz\.|Authz|"
    r"GetSigner\s*\(|GetSigners\s*\(|msg\.GetSigner\s*\(|"
    r"msg\.Sender|msg\.Signer|msg\.Owner|request\.Signer|ctx\.MsgSender|"
    r"subaccount\.Owner|SubaccountId\.Owner|SubaccountID\.Owner|"
    r"\.Owner\s*==|\bowner\s*==|\.Equals\s*\(|AccAddressFromBech32)"
)

_ONLY_LOAD_NO_IMPACT_RE = re.compile(
    r"func\s+[^{]+\{[^{}]*(?:return\s+msg\.[A-Za-z0-9_.]+|return\s+nil)\s*\}",
    re.S,
)


def _message_for(name: str, reason: str) -> str:
    return (
        f"`{name}` appears to trust a caller-supplied subaccount/account id "
        f"without binding it to the signer, owner, or delegated authority "
        f"before authorization or state mutation ({reason}). "
        f"Require an owner/authz check for the affected id. "
        f"(class: sub-account-isolation-bypass)"
    )


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
        full_text = engine.text(fn)

        if not _SUBACCOUNT_RE.search(body_text):
            continue
        if not _CALLER_SUPPLIED_ID_RE.search(body_text):
            continue

        fail_open_auth_filter = (
            _AUTHISH_NAME_RE.search(name)
            and _REQUEST_SWITCH_RE.search(body_text)
            and _DEFAULT_ALLOW_RE.search(body_text)
            and not _FAIL_CLOSED_RE.search(body_text)
        )

        unbound_mutation = (
            _HANDLER_NAME_RE.search(name)
            and _SUBACCOUNT_MUTATION_RE.search(body_text)
            and not _AUTHZ_BINDING_RE.search(body_text)
            and not _ONLY_LOAD_NO_IMPACT_RE.search(full_text)
        )

        if not (fail_open_auth_filter or unbound_mutation):
            continue

        reason = "fail-open subaccount authenticator"
        if unbound_mutation and not fail_open_auth_filter:
            reason = "unbound subaccount/account mutation"

        hits.append({
            "severity": "high",
            "line": engine.line(fn),
            "col": engine.col(fn),
            "snippet": full_text.splitlines()[0][:160],
            "message": _message_for(name, reason),
        })
    return hits

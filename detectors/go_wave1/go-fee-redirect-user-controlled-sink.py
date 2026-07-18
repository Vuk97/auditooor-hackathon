"""
go-fee-redirect-user-controlled-sink.py

Detects Go fee, rebate, commission, or accrual payout paths that send a
fee-like value to a user-controlled account sink without first checking that
sink against a configured collector, module account, or canonical recipient.

This detector is intentionally distinct from the transfer-out recipient
binding detectors and the rewards-distribution module-recipient detector:

1. It requires fee/rebate/commission/accrual context.
2. It requires a value-moving sink whose amount or source is fee-like.
3. It requires the sink recipient to be user-derived from a Msg/request/order
   field or from an address-like function parameter.
4. It suppresses functions with explicit collector, module-account, or
   canonical-recipient validation.

The detector is recall-oriented only. A hit is not a filing verdict.
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.go-fee-redirect-user-controlled-sink"

_FEE_CONTEXT_RE = re.compile(
    r"(fee|fees|feeCollector|protocolFee|tradingFee|makerFee|takerFee"
    r"|rebate|commission|referrer|affiliate|integrator|accru|accrual)",
    re.IGNORECASE,
)

_FEE_VALUE_RE = re.compile(
    r"(fee|fees|protocolFee|tradingFee|makerFee|takerFee|rebate|commission"
    r"|accrued|accrual|collector|affiliate|integrator|referrer)",
    re.IGNORECASE,
)

_USER_FIELD_RE = re.compile(
    r"\b(?:msg|req|request|order|trade|settlement|input|payload)\."
    r"[A-Za-z_]\w*(?:Recipient|Receiver|Address|Addr|Sink|Referrer"
    r"|Affiliate|Integrator|Beneficiary|Payout|Payee|User)[A-Za-z_]*\b"
)

_USER_PARAM_NAME_RE = re.compile(
    r"^(?:to|recipient|receiver|sink|payee|beneficiary|referrer|affiliate"
    r"|integrator|feeRecipient|feeSink|rebateRecipient|rebateAddr"
    r"|commissionRecipient|commissionAddr|payoutRecipient|payoutAddr)$",
    re.IGNORECASE,
)

_ADDRESS_PARAM_RE = re.compile(
    r"(?P<names>[A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s+"
    r"(?:(?:sdk|common|types)\.)?"
    r"(?:AccAddress|Address|Addr|string)\b"
)

_ASSIGN_RE = re.compile(r"\b([A-Za-z_]\w*)\s*(?::=|=)\s*([^;\n]+)")

_SINK_CALL_PREFIX_RE = re.compile(
    r"\b(?P<name>SendCoinsFromModuleToAccount|SendCoins|Transfer"
    r"|PayFee|PayFees|PayRebate|PayCommission|CreditFee|CreditRebate"
    r"|CreditCommission|PayoutFee|PayoutRebate|PayoutCommission)\s*\(",
    re.IGNORECASE,
)

_RECIPIENT_ARG_INDEXES = {
    "sendcoinsfrommoduletoaccount": (2,),
    "sendcoins": (2,),
    "transfer": (0, 1),
    "payfee": (0, 1, 2),
    "payfees": (0, 1, 2),
    "payrebate": (0, 1, 2),
    "paycommission": (0, 1, 2),
    "creditfee": (0, 1, 2),
    "creditrebate": (0, 1, 2),
    "creditcommission": (0, 1, 2),
    "payoutfee": (0, 1, 2),
    "payoutrebate": (0, 1, 2),
    "payoutcommission": (0, 1, 2),
}

_AMOUNT_ARG_INDEXES = {
    "sendcoinsfrommoduletoaccount": (3,),
    "sendcoins": (3,),
    "transfer": (1, 2),
    "payfee": (1, 2, 3),
    "payfees": (1, 2, 3),
    "payrebate": (1, 2, 3),
    "paycommission": (1, 2, 3),
    "creditfee": (1, 2, 3),
    "creditrebate": (1, 2, 3),
    "creditcommission": (1, 2, 3),
    "payoutfee": (1, 2, 3),
    "payoutrebate": (1, 2, 3),
    "payoutcommission": (1, 2, 3),
}

_CONFIGURED_SINK_RE = re.compile(
    r"(FeeCollector|feeCollector|ProtocolFeeCollector|CollectorAddress"
    r"|ConfiguredFee|ConfiguredCollector|CanonicalFee|CanonicalRecipient"
    r"|ExpectedFee|ExpectedRecipient|Treasury|CommunityPool"
    r"|GetFeeCollector|GetCollector|GetModuleAddress|FeeCollectorName"
    r"|ModuleAccount|ModuleName)",
    re.IGNORECASE,
)

_NAMED_GUARD_RE = re.compile(
    r"(ValidateFeeRecipient|ValidateFeeSink|ValidateCollectorRecipient"
    r"|ValidateCanonicalRecipient|ValidateModuleAccountRecipient"
    r"|EnsureFeeRecipient|EnsureFeeSink|EnsureCollectorRecipient"
    r"|AssertFeeRecipient|AssertCollectorRecipient|AllowedFeeRecipient"
    r"|IsAllowedFeeRecipient|IsConfiguredFeeRecipient"
    r"|IsModuleAccount|GetModuleAccount|GetModuleAddress|BlockedAddr"
    r"|IsBlockedAddr)",
    re.IGNORECASE,
)

_COMPARISON_RE = re.compile(r"(?:==|!=|\.Equal\s*\(|\.Equals\s*\(|bytes\.Equal\s*\()")
_STRING_RE = re.compile(r'`[^`]*`|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'' )


def _blank_comment(match: re.Match[str]) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in match.group(0))


def _strip_comments(src: str) -> str:
    src = re.sub(r"//.*", _blank_comment, src)
    return re.sub(r"/\*.*?\*/", _blank_comment, src, flags=re.S)


def _strip_comments_and_strings(src: str) -> str:
    src = _strip_comments(src)
    return _STRING_RE.sub(_blank_comment, src)


def _split_call_args(call_text: str) -> list[str]:
    start = call_text.find("(")
    end = call_text.rfind(")")
    if start < 0 or end <= start:
        return []
    args_text = call_text[start + 1 : end]
    args: list[str] = []
    current: list[str] = []
    depth = 0
    for ch in args_text:
        if ch == "," and depth == 0:
            args.append("".join(current).strip())
            current = []
            continue
        current.append(ch)
        if ch in "([{":
            depth += 1
        elif ch in ")]}" and depth > 0:
            depth -= 1
    if current or args_text.strip():
        args.append("".join(current).strip())
    return args


def _function_header(fn_text: str) -> str:
    return fn_text.split("{", 1)[0]


def _address_params(fn_text: str) -> set[str]:
    params: set[str] = set()
    for match in _ADDRESS_PARAM_RE.finditer(_function_header(fn_text)):
        for name in match.group("names").split(","):
            name = name.strip()
            if _USER_PARAM_NAME_RE.match(name):
                params.add(name)
    return params


def _clean_expr(expr: str) -> str:
    return expr.strip().strip("&*").strip()


def _expr_mentions_any(expr: str, terms: set[str]) -> bool:
    for term in terms:
        if "." in term:
            if term in expr:
                return True
            continue
        if re.search(rf"\b{re.escape(term)}\b", expr):
            return True
    return False


def _is_configured_sink(expr: str) -> bool:
    expr = _clean_expr(expr)
    if _USER_FIELD_RE.search(expr):
        return False
    return bool(_CONFIGURED_SINK_RE.search(expr))


def _seed_user_terms(fn_text: str, body_text: str) -> set[str]:
    terms = set(_USER_FIELD_RE.findall(body_text))
    terms.update(_address_params(fn_text))
    return terms


def _expand_user_aliases(body_text: str, terms: set[str]) -> set[str]:
    aliases = set(terms)
    for line in body_text.splitlines():
        match = _ASSIGN_RE.search(line)
        if not match:
            continue
        lhs = match.group(1)
        rhs = match.group(2)
        if _is_configured_sink(rhs):
            aliases.discard(lhs)
            continue
        if _expr_mentions_any(rhs, aliases):
            aliases.add(lhs)
        elif lhs in aliases and _USER_PARAM_NAME_RE.match(lhs):
            continue
        elif lhs in aliases:
            aliases.discard(lhs)
    return aliases


def _call_spans(body_text: str) -> list[str]:
    spans: list[str] = []
    current: list[str] = []
    depth = 0
    for line in body_text.splitlines():
        if current:
            current.append(line)
            depth += line.count("(") - line.count(")")
            if depth <= 0:
                spans.append("\n".join(current))
                current = []
            continue
        if not _SINK_CALL_PREFIX_RE.search(line):
            continue
        current = [line]
        depth = line.count("(") - line.count(")")
        if depth <= 0:
            spans.append(line)
            current = []
    return spans


def _fee_like_transfer(call_name: str, args: list[str]) -> bool:
    indexes = _AMOUNT_ARG_INDEXES.get(call_name.lower(), ())
    if any(idx < len(args) and _FEE_VALUE_RE.search(args[idx]) for idx in indexes):
        return True
    if call_name.lower() == "sendcoinsfrommoduletoaccount" and len(args) > 1:
        return bool(_FEE_VALUE_RE.search(args[1]))
    return bool(_FEE_VALUE_RE.search(call_name))


def _user_recipient_args(call_name: str, args: list[str], terms: set[str]) -> list[str]:
    recipient_args: list[str] = []
    indexes = _RECIPIENT_ARG_INDEXES.get(call_name.lower(), ())
    for idx in indexes:
        if idx >= len(args):
            continue
        expr = _clean_expr(args[idx])
        if _is_configured_sink(expr):
            continue
        if _expr_mentions_any(expr, terms):
            recipient_args.append(expr)
    return recipient_args


def _has_configured_guard(body_text: str, user_terms: set[str]) -> bool:
    for line in body_text.splitlines():
        if not _expr_mentions_any(line, user_terms):
            continue
        if _NAMED_GUARD_RE.search(line):
            return True
        if _CONFIGURED_SINK_RE.search(line) and _COMPARISON_RE.search(line):
            return True
        if _CONFIGURED_SINK_RE.search(line) and re.search(r"\bif\b|return\b", line):
            return True
    return False


def _fee_redirect_reason(body_text: str, terms: set[str]) -> str | None:
    for call_text in _call_spans(body_text):
        match = _SINK_CALL_PREFIX_RE.search(call_text)
        if not match:
            continue
        call_name = match.group("name")
        args = _split_call_args(call_text)
        if not _fee_like_transfer(call_name, args):
            continue
        recipients = _user_recipient_args(call_name, args, terms)
        if recipients:
            return (
                f"{call_name} routes fee-like value to user-controlled sink "
                f"`{recipients[0]}`"
            )
    return None


def run(engine, filepath: str):
    hits = []
    for fn in engine.functions():
        name = engine.fn_name(fn)
        if not name or name == "?":
            continue
        body = engine.fn_body(fn)
        if body is None:
            continue

        fn_text = engine.text(fn)
        body_text = _strip_comments_and_strings(engine.text(body))
        fn_text_clean = _strip_comments_and_strings(fn_text)

        if not (_FEE_CONTEXT_RE.search(name) or _FEE_CONTEXT_RE.search(fn_text_clean)):
            continue

        terms = _expand_user_aliases(body_text, _seed_user_terms(fn_text, body_text))
        if not terms:
            continue

        reason = _fee_redirect_reason(body_text, terms)
        if reason is None:
            continue
        if _has_configured_guard(body_text, terms):
            continue

        hits.append(
            {
                "severity": "high",
                "line": engine.line(fn),
                "col": engine.col(fn),
                "snippet": fn_text.splitlines()[0][:160],
                "message": (
                    f"`{name}` has a fee-redirect sink gap: {reason} without "
                    f"checking it against the configured collector, module "
                    f"account, or canonical recipient. "
                    f"(class: fee-redirect)"
                ),
            }
        )

    return hits

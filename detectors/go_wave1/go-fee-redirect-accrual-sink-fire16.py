"""
go-fee-redirect-accrual-sink-fire16.py

Fire16 Go lift for fee-redirect accrual sink mismatch.

Source Solidity seeds:
- amm-reserves-fee-conflation
- fee-calculation-accrual-missing
- auction-trigger-fee-paid-from-pooled-balance

This detector looks for fee, reward, rebate, commission, or accrual value
sent to an unchecked dynamic sink, and gives a stronger reason when the
function records entitlement for one party but funds a different sink.
It is recall-oriented only. A hit is not a filing verdict.
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.go-fee-redirect-accrual-sink-fire16"

_FEE_CONTEXT_RE = re.compile(
    r"(fee|fees|protocolFee|tradingFee|makerFee|takerFee|rebate|commission"
    r"|reward|rewards|accru|accrual|entitlement|owed|claim|auction"
    r"|collector|treasury|affiliate|integrator|referrer)",
    re.IGNORECASE,
)

_FEE_VALUE_RE = re.compile(
    r"(fee|fees|protocolFee|tradingFee|makerFee|takerFee|rebate|commission"
    r"|reward|rewards|accrued|accrual|entitlement|owed|claimable"
    r"|collector|treasury|affiliate|integrator|referrer)",
    re.IGNORECASE,
)

_DYNAMIC_FIELD_RE = re.compile(
    r"\b(?:msg|req|request|order|trade|settlement|input|payload|user|account"
    r"|cfg|config|settings)\.(?:[A-Za-z_]\w*)?(?:FeeSink|FeeCollector"
    r"|FeeRecipient|RewardSink|RewardCollector|RewardRecipient"
    r"|CommissionSink|CommissionRecipient|RebateSink|RebateRecipient"
    r"|AccrualSink|Collector|Recipient|Receiver|Address|Addr|Sink"
    r"|Referrer|Affiliate|Integrator|Beneficiary|Payout|Payee|User)"
    r"[A-Za-z_]*\b"
)

_DYNAMIC_PARAM_NAME_RE = re.compile(
    r"^(?:to|recipient|receiver|sink|payee|beneficiary|collector"
    r"|feeRecipient|feeSink|feeCollector|rewardRecipient|rewardSink"
    r"|rewardCollector|rebateRecipient|rebateSink|commissionRecipient"
    r"|commissionSink|accrualSink|payoutRecipient|payoutAddr)$",
    re.IGNORECASE,
)

_ADDRESS_PARAM_RE = re.compile(
    r"(?P<names>[A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s+"
    r"(?:(?:sdk|common|types)\.)?"
    r"(?:AccAddress|Address|Addr|string)\b"
)

_ASSIGN_RE = re.compile(r"\b([A-Za-z_]\w*)\s*(?::=|=)\s*([^;\n]+)")

_SINK_CALL_RE = re.compile(
    r"\b(?P<name>SendCoinsFromModuleToAccount|SendCoinsFromAccountToAccount"
    r"|SendCoins|Transfer|TransferFee|TransferReward|PayFee|PayFees"
    r"|PayRebate|PayCommission|PayReward|PayRewards|CreditFee"
    r"|CreditRebate|CreditCommission|CreditReward|CreditRewards"
    r"|PayoutFee|PayoutRebate|PayoutCommission|PayoutReward|PayoutRewards"
    r"|DistributeRewards|SendReward|SendRewards|SettleFee|SettleReward"
    r"|FundFeeSink|FundRewardSink)\s*\(",
    re.IGNORECASE,
)

_RECIPIENT_ARG_INDEXES = {
    "sendcoinsfrommoduletoaccount": (2,),
    "sendcoinsfromaccounttoaccount": (2,),
    "sendcoins": (2,),
    "transfer": (0, 1),
    "transferfee": (0, 1, 2),
    "transferreward": (0, 1, 2),
    "payfee": (0, 1, 2),
    "payfees": (0, 1, 2),
    "payrebate": (0, 1, 2),
    "paycommission": (0, 1, 2),
    "payreward": (0, 1, 2),
    "payrewards": (0, 1, 2),
    "creditfee": (0, 1, 2),
    "creditrebate": (0, 1, 2),
    "creditcommission": (0, 1, 2),
    "creditreward": (0, 1, 2),
    "creditrewards": (0, 1, 2),
    "payoutfee": (0, 1, 2),
    "payoutrebate": (0, 1, 2),
    "payoutcommission": (0, 1, 2),
    "payoutreward": (0, 1, 2),
    "payoutrewards": (0, 1, 2),
    "distributerewards": (0, 1, 2),
    "sendreward": (0, 1, 2),
    "sendrewards": (0, 1, 2),
    "settlefee": (0, 1, 2),
    "settlereward": (0, 1, 2),
    "fundfeesink": (0, 1, 2),
    "fundrewardsink": (0, 1, 2),
}

_AMOUNT_ARG_INDEXES = {
    "sendcoinsfrommoduletoaccount": (1, 3),
    "sendcoinsfromaccounttoaccount": (3,),
    "sendcoins": (1, 3),
    "transfer": (1, 2),
    "transferfee": (1, 2, 3),
    "transferreward": (1, 2, 3),
    "payfee": (1, 2, 3),
    "payfees": (1, 2, 3),
    "payrebate": (1, 2, 3),
    "paycommission": (1, 2, 3),
    "payreward": (1, 2, 3),
    "payrewards": (1, 2, 3),
    "creditfee": (1, 2, 3),
    "creditrebate": (1, 2, 3),
    "creditcommission": (1, 2, 3),
    "creditreward": (1, 2, 3),
    "creditrewards": (1, 2, 3),
    "payoutfee": (1, 2, 3),
    "payoutrebate": (1, 2, 3),
    "payoutcommission": (1, 2, 3),
    "payoutreward": (1, 2, 3),
    "payoutrewards": (1, 2, 3),
    "distributerewards": (1, 2, 3),
    "sendreward": (1, 2, 3),
    "sendrewards": (1, 2, 3),
    "settlefee": (1, 2, 3),
    "settlereward": (1, 2, 3),
    "fundfeesink": (1, 2, 3),
    "fundrewardsink": (1, 2, 3),
}

_FIXED_SINK_RE = re.compile(
    r"(types\.|authtypes\.|distrtypes\.|minttypes\.|FeeCollectorName"
    r"|RewardCollectorName|CommunityPoolName|TreasuryName|ModuleName"
    r"|ModuleAccountName|ProtocolFeeCollector|CanonicalFeeCollector"
    r"|CanonicalRewardCollector|ConfiguredCollector|ExpectedCollector"
    r"|params\.(?:FeeCollector|RewardCollector|ProtocolFeeCollector"
    r"|Treasury|CommunityPool)"
    r"|DefaultFeeCollector|GetFeeCollector\s*\(|GetCollector\s*\("
    r"|GetTreasury\s*\(|GetCommunityPool\s*\(|GetModuleAddress\s*\("
    r"|GetModuleAccount\s*\(|ModuleAccount|CommunityPool|Treasury)",
    re.IGNORECASE,
)

_GUARD_RE = re.compile(
    r"(ValidateFeeRecipient|ValidateFeeSink|ValidateCollectorRecipient"
    r"|ValidateRewardRecipient|ValidateRewardSink|ValidateCanonicalRecipient"
    r"|ValidateModuleAccountRecipient|EnsureFeeRecipient|EnsureFeeSink"
    r"|EnsureCollectorRecipient|EnsureRewardRecipient|EnsureRewardSink"
    r"|AssertFeeRecipient|AssertCollectorRecipient|AllowedFeeRecipient"
    r"|AllowedRewardRecipient|AllowedFeeSink|AllowedRewardSink"
    r"|IsAllowedFeeRecipient|IsAllowedRewardRecipient|IsAllowedFeeSink"
    r"|IsAllowedRewardSink|IsConfiguredFeeRecipient"
    r"|IsConfiguredRewardRecipient|IsModuleAccount|GetModuleAccount"
    r"|GetModuleAddress|BlockedAddr|IsBlockedAddr|IsAllowlistedSink"
    r"|CheckFeeSinkPolicy|CheckRewardSinkPolicy|RequireAllowedSink)",
    re.IGNORECASE,
)

_COMPARISON_RE = re.compile(r"(?:==|!=|\.Equal\s*\(|\.Equals\s*\(|bytes\.Equal\s*\()")

_ENTITLEMENT_WRITE_RE = re.compile(
    r"(?P<store>[A-Za-z_][A-Za-z0-9_\.]*(?:Entitlement|Entitlements"
    r"|Accrued|Accrual|Owed|Claimable|RewardDebt|FeeDebt|Rebate"
    r"|Commission)[A-Za-z0-9_\.]*)\s*"
    r"(?:\[\s*(?P<who>[^\]\n]+)\s*\])?\s*(?:\+=|=)"
    r"\s*(?P<value>[^;\n]+)",
    re.IGNORECASE,
)

_ENTITLEMENT_CALL_RE = re.compile(
    r"\b(?P<name>RecordFeeEntitlement|AccrueFee|AccrueReward"
    r"|RecordRewardEntitlement|RecordCommission|RecordRebate"
    r"|AddFeeEntitlement|AddRewardEntitlement)\s*\(",
    re.IGNORECASE,
)

_STRING_RE = re.compile(r'`[^`]*`|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'' )


def _blank(match: re.Match[str]) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in match.group(0))


def _strip_comments(src: str) -> str:
    src = re.sub(r"//.*", _blank, src)
    return re.sub(r"/\*.*?\*/", _blank, src, flags=re.S)


def _strip_comments_and_strings(src: str) -> str:
    return _STRING_RE.sub(_blank, _strip_comments(src))


def _clean_expr(expr: str) -> str:
    return expr.strip().strip("&*").strip()


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


def _balanced_call(src: str, open_paren: int) -> str | None:
    depth = 0
    for idx in range(open_paren, len(src)):
        ch = src[idx]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return src[open_paren:idx + 1]
    return None


def _function_header(fn_text: str) -> str:
    return fn_text.split("{", 1)[0]


def _address_params(fn_text: str) -> set[str]:
    params: set[str] = set()
    for match in _ADDRESS_PARAM_RE.finditer(_function_header(fn_text)):
        for name in match.group("names").split(","):
            name = name.strip()
            if _DYNAMIC_PARAM_NAME_RE.match(name):
                params.add(name)
    return params


def _expr_mentions_any(expr: str, terms: set[str]) -> bool:
    for term in terms:
        if "." in term or "(" in term or "[" in term:
            if term in expr:
                return True
            continue
        if re.search(rf"\b{re.escape(term)}\b", expr):
            return True
    return False


def _is_fixed_sink(expr: str) -> bool:
    expr = _clean_expr(expr)
    if _DYNAMIC_FIELD_RE.search(expr):
        return False
    return bool(_FIXED_SINK_RE.search(expr))


def _seed_dynamic_terms(fn_text: str, body_text: str) -> set[str]:
    terms = {match.group(0).strip() for match in _DYNAMIC_FIELD_RE.finditer(body_text)}
    terms.update(_address_params(fn_text))
    return terms


def _expand_dynamic_aliases(body_text: str, terms: set[str]) -> set[str]:
    aliases = set(terms)
    for line in body_text.splitlines():
        match = _ASSIGN_RE.search(line)
        if not match:
            continue
        lhs = match.group(1)
        rhs = match.group(2)
        if _is_fixed_sink(rhs):
            aliases.discard(lhs)
            continue
        if _DYNAMIC_FIELD_RE.search(rhs) or _expr_mentions_any(rhs, aliases):
            aliases.add(lhs)
        elif lhs in aliases and _DYNAMIC_PARAM_NAME_RE.match(lhs):
            continue
        elif lhs in aliases:
            aliases.discard(lhs)
    return aliases


def _has_guard(body_text: str, dynamic_terms: set[str]) -> bool:
    for line in body_text.splitlines():
        if _SINK_CALL_RE.search(line):
            continue
        mentions_dynamic = (
            _DYNAMIC_FIELD_RE.search(line) or _expr_mentions_any(line, dynamic_terms)
        )
        if not mentions_dynamic:
            continue
        if _GUARD_RE.search(line):
            return True
        if _FIXED_SINK_RE.search(line) and _COMPARISON_RE.search(line):
            return True
        if re.search(r"\bif\b", line) and re.search(r"\ballowed[A-Za-z_]*\s*\[", line, re.I):
            return True
    return False


def _call_spans(body_text: str, call_re: re.Pattern[str]) -> list[tuple[str, str]]:
    spans: list[tuple[str, str]] = []
    for match in call_re.finditer(body_text):
        call = _balanced_call(body_text, match.end() - 1)
        if call is not None:
            spans.append((match.group("name"), call))
    return spans


def _fee_like_transfer(call_name: str, args: list[str]) -> bool:
    indexes = _AMOUNT_ARG_INDEXES.get(call_name.lower(), ())
    if any(idx < len(args) and _FEE_VALUE_RE.search(args[idx]) for idx in indexes):
        return True
    return bool(_FEE_VALUE_RE.search(call_name))


def _dynamic_recipient_args(
    call_name: str,
    args: list[str],
    dynamic_terms: set[str],
) -> list[str]:
    out: list[str] = []
    for idx in _RECIPIENT_ARG_INDEXES.get(call_name.lower(), ()):
        if idx >= len(args):
            continue
        expr = _clean_expr(args[idx])
        if _is_fixed_sink(expr):
            continue
        if _DYNAMIC_FIELD_RE.search(expr) or _expr_mentions_any(expr, dynamic_terms):
            out.append(expr)
    return out


def _entitlement_targets(body_text: str, dynamic_terms: set[str]) -> list[str]:
    targets: list[str] = []
    for match in _ENTITLEMENT_WRITE_RE.finditer(body_text):
        value = match.group("value")
        if not (_FEE_VALUE_RE.search(match.group("store")) or _FEE_VALUE_RE.search(value)):
            continue
        who = _clean_expr(match.group("who") or "")
        if who and not _is_fixed_sink(who):
            targets.append(who)

    for call_name, call_text in _call_spans(body_text, _ENTITLEMENT_CALL_RE):
        args = _split_call_args(call_text)
        if len(args) < 2:
            continue
        if not (any(_FEE_VALUE_RE.search(arg) for arg in args) or _FEE_VALUE_RE.search(call_name)):
            continue
        candidate = _clean_expr(args[1])
        if candidate and not _is_fixed_sink(candidate):
            targets.append(candidate)

    expanded: list[str] = []
    for target in targets:
        if _DYNAMIC_FIELD_RE.search(target) or _expr_mentions_any(target, dynamic_terms):
            expanded.append(target)
    return expanded


def _same_expr(left: str, right: str) -> bool:
    left = _clean_expr(left)
    right = _clean_expr(right)
    if left == right:
        return True
    if re.search(rf"\b{re.escape(left)}\b", right):
        return True
    if re.search(rf"\b{re.escape(right)}\b", left):
        return True
    return False


def _fee_redirect_reason(body_text: str, dynamic_terms: set[str]) -> str | None:
    entitlement_targets = _entitlement_targets(body_text, dynamic_terms)
    for call_name, call_text in _call_spans(body_text, _SINK_CALL_RE):
        args = _split_call_args(call_text)
        if not _fee_like_transfer(call_name, args):
            continue
        recipients = _dynamic_recipient_args(call_name, args, dynamic_terms)
        if not recipients:
            continue
        recipient = recipients[0]
        for target in entitlement_targets:
            if not _same_expr(target, recipient):
                return (
                    f"records fee entitlement for `{target}` but {call_name} "
                    f"funds dynamic sink `{recipient}`"
                )
        return f"{call_name} routes fee-like value to unchecked dynamic sink `{recipient}`"
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
        clean_fn_text = _strip_comments_and_strings(fn_text)
        if not (_FEE_CONTEXT_RE.search(name) or _FEE_CONTEXT_RE.search(clean_fn_text)):
            continue

        dynamic_terms = _expand_dynamic_aliases(body_text, _seed_dynamic_terms(fn_text, body_text))
        if not dynamic_terms:
            continue
        if _has_guard(body_text, dynamic_terms):
            continue

        reason = _fee_redirect_reason(body_text, dynamic_terms)
        if reason is None:
            continue

        hits.append(
            {
                "severity": "high",
                "line": engine.line(fn),
                "col": engine.col(fn),
                "snippet": fn_text.splitlines()[0][:160],
                "message": (
                    f"`{name}` has a fee-redirect accrual sink gap: {reason} "
                    f"without validating the sink against a fixed collector, "
                    f"module account, or allowlist. (class: fee-redirect)"
                ),
            }
        )
    return hits

"""
go-fee-redirect-msg-signer-controlled-collector.py

Detects Go fee, rebate, commission, or reward payout paths where the
protocol collector sink is replaced with a message signer or signer-derived
address without validating that address against the configured collector,
treasury, module account, or allowlist.

This detector is deliberately narrower than go-fee-redirect-user-controlled-
sink.py. It targets signer-derived collectors such as msg.GetSigners()[0],
msg.Signer, msg.Sender, req.Signer, or ctx.MsgSender() rather than explicit
recipient fields like msg.FeeRecipient.

The detector is recall-oriented only. A hit is not a filing verdict.
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.go-fee-redirect-msg-signer-controlled-collector"

_FEE_CONTEXT_RE = re.compile(
    r"(fee|fees|feeCollector|protocolFee|tradingFee|makerFee|takerFee"
    r"|rebate|commission|reward|rewards|distribute|collector|treasury"
    r"|affiliate|integrator|referrer)",
    re.IGNORECASE,
)

_FEE_VALUE_RE = re.compile(
    r"(fee|fees|protocolFee|tradingFee|makerFee|takerFee|rebate|commission"
    r"|reward|rewards|collector|treasury|affiliate|integrator|referrer)",
    re.IGNORECASE,
)

_SIGNER_SOURCE_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:(?:msg|req|request|payload|input)\."
    r"(?:GetSigners?|Signer|Sender|Creator|FromAddress|FromAddr)"
    r"(?:\s*\(\s*\))?(?:\s*\[[^\]]+\])?"
    r"|ctx\.MsgSender\s*\(\s*\))"
)

_ASSIGN_RE = re.compile(r"\b([A-Za-z_]\w*)\s*(?::=|=)\s*([^;\n]+)")

_SINK_CALL_PREFIX_RE = re.compile(
    r"\b(?P<name>SendCoinsFromModuleToAccount|SendCoins|Transfer"
    r"|PayFee|PayFees|PayRebate|PayCommission|PayReward|PayRewards"
    r"|CreditFee|CreditRebate|CreditCommission|CreditReward|CreditRewards"
    r"|PayoutFee|PayoutRebate|PayoutCommission|PayoutReward|PayoutRewards"
    r"|DistributeRewards|SendReward|SendRewards)\s*\(",
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
}

_AMOUNT_ARG_INDEXES = {
    "sendcoinsfrommoduletoaccount": (1, 3),
    "sendcoins": (1, 3),
    "transfer": (1, 2),
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
}

_CONFIGURED_COLLECTOR_RE = re.compile(
    r"(FeeCollector|feeCollector|ProtocolFeeCollector|CollectorAddress"
    r"|ConfiguredFee|ConfiguredCollector|CanonicalFee|CanonicalRecipient"
    r"|ExpectedFee|ExpectedRecipient|Treasury|CommunityPool|RewardCollector"
    r"|RewardModule|GetFeeCollector|GetCollector|GetTreasury"
    r"|GetModuleAddress|FeeCollectorName|ModuleAccount|ModuleName"
    r"|AllowedFeeRecipient|AllowedRewardRecipient|AllowlistedSink)",
    re.IGNORECASE,
)

_NAMED_GUARD_RE = re.compile(
    r"(ValidateFeeRecipient|ValidateFeeSink|ValidateCollectorRecipient"
    r"|ValidateRewardRecipient|ValidateCanonicalRecipient"
    r"|ValidateModuleAccountRecipient|EnsureFeeRecipient|EnsureFeeSink"
    r"|EnsureCollectorRecipient|EnsureRewardRecipient"
    r"|AssertFeeRecipient|AssertCollectorRecipient|AllowedFeeRecipient"
    r"|AllowedRewardRecipient|IsAllowedFeeRecipient"
    r"|IsAllowedRewardRecipient|IsConfiguredFeeRecipient"
    r"|IsConfiguredRewardRecipient|IsModuleAccount|GetModuleAccount"
    r"|GetModuleAddress|BlockedAddr|IsBlockedAddr|IsAllowlistedSink)",
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


def _clean_expr(expr: str) -> str:
    return expr.strip().strip("&*").strip()


def _expr_mentions_any(expr: str, terms: set[str]) -> bool:
    for term in terms:
        if "." in term or "(" in term or "[" in term:
            if term in expr:
                return True
            continue
        if re.search(rf"\b{re.escape(term)}\b", expr):
            return True
    return False


def _is_configured_collector(expr: str) -> bool:
    expr = _clean_expr(expr)
    if _SIGNER_SOURCE_RE.search(expr):
        return False
    return bool(_CONFIGURED_COLLECTOR_RE.search(expr))


def _seed_signer_terms(body_text: str) -> set[str]:
    return {match.group(0).strip() for match in _SIGNER_SOURCE_RE.finditer(body_text)}


def _expand_signer_aliases(body_text: str, terms: set[str]) -> set[str]:
    aliases = set(terms)
    for line in body_text.splitlines():
        match = _ASSIGN_RE.search(line)
        if not match:
            continue
        lhs = match.group(1)
        rhs = match.group(2)
        if _is_configured_collector(rhs):
            aliases.discard(lhs)
            continue
        if _SIGNER_SOURCE_RE.search(rhs) or _expr_mentions_any(rhs, aliases):
            aliases.add(lhs)
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
    return bool(_FEE_VALUE_RE.search(call_name))


def _signer_recipient_args(call_name: str, args: list[str], terms: set[str]) -> list[str]:
    recipient_args: list[str] = []
    indexes = _RECIPIENT_ARG_INDEXES.get(call_name.lower(), ())
    for idx in indexes:
        if idx >= len(args):
            continue
        expr = _clean_expr(args[idx])
        if _is_configured_collector(expr):
            continue
        if _SIGNER_SOURCE_RE.search(expr) or _expr_mentions_any(expr, terms):
            recipient_args.append(expr)
    return recipient_args


def _has_configured_guard(body_text: str, signer_terms: set[str]) -> bool:
    for line in body_text.splitlines():
        if not _expr_mentions_any(line, signer_terms) and not _SIGNER_SOURCE_RE.search(line):
            continue
        if _NAMED_GUARD_RE.search(line):
            return True
        if _CONFIGURED_COLLECTOR_RE.search(line) and _COMPARISON_RE.search(line):
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
        recipients = _signer_recipient_args(call_name, args, terms)
        if recipients:
            return (
                f"{call_name} routes fee or reward value to signer-controlled "
                f"collector `{recipients[0]}`"
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

        terms = _expand_signer_aliases(body_text, _seed_signer_terms(body_text))
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
                    f"`{name}` has a fee-redirect collector substitution: "
                    f"{reason} without checking the signer against the "
                    f"configured collector, treasury, module account, or "
                    f"allowlisted sink. (class: fee-redirect)"
                ),
            }
        )

    return hits

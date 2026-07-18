"""
go-rewards-sink-policy-missing.py

Companion Go detector for rewards-distribution-skew recall.

It looks for reward or distribution code that sends value through Cosmos bank
keepers into an account recipient or dynamic module account without a local
blocked-address, module-account, or reward-sink allowlist check. This is a
separate same-class recall arm for the blocked-module-recipient fixture.
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.go-rewards-sink-policy-missing"

_REWARD_CONTEXT_RE = re.compile(
    r"(Reward|Rewards|Distribution|Distribute|DelegatorReward|ValidatorReward"
    r"|Commission|Incentive|Emission|FeeCollector|CommunityPool|PendingReward"
    r"|RewardModule|RewardsModule)",
    re.IGNORECASE,
)

_SEND_CALL_RE = re.compile(
    r"\b(?P<name>SendCoinsFromModuleToAccount|SendCoinsFromModuleToModule"
    r"|PayReward|PayRewards|CreditReward|CreditRewards|PayoutReward"
    r"|PayoutRewards|SendReward|SendRewards|DistributeRewards)\s*\(",
    re.IGNORECASE,
)

_POLICY_GUARD_RE = re.compile(
    r"(BlockedAddr\s*\(|IsBlockedAddr\s*\(|blockedAddrs\s*\["
    r"|IsSanctioned\s*\(|IsFrozen\s*\(|FrozenAddr\s*\("
    r"|GetModuleAccount\s*\(|GetModuleAddress\s*\(|IsModuleAccount\s*\("
    r"|ValidateRewardRecipient\s*\(|ValidateRecipient\s*\("
    r"|ValidateModuleAccountRecipient\s*\(|AllowedRewardRecipient"
    r"|IsAllowedRewardRecipient|AllowedRewardModule|IsAllowedRewardModule"
    r"|ValidateRewardModule|ExpectedRewardModule|AllowedModuleAccount"
    r"|ReceivableModule|ModuleAccountAddrs|AllowlistedRewardSink)",
    re.IGNORECASE,
)

_CONFIGURED_SINK_RE = re.compile(
    r"(types\.|authtypes\.|distrtypes\.|minttypes\.|RewardModuleName"
    r"|RewardsModuleName|FeeCollectorName|CommunityPoolName"
    r"|PendingRewardForDelegatorAccountName|ModuleName|ModuleAccountName"
    r"|GetModuleAddress\s*\(|GetFeeCollector\s*\(|GetCommunityPool\s*\()",
    re.IGNORECASE,
)

_DYNAMIC_SINK_RE = re.compile(
    r"(^|\b)(to|toAddr|recipient|receiver|sink|payee|beneficiary"
    r"|msg\.[A-Za-z_]\w*|req\.[A-Za-z_]\w*|request\.[A-Za-z_]\w*"
    r"|[A-Za-z_]\w*(?:Recipient|Receiver|Sink|Payee|Beneficiary"
    r"|Account|Address|Addr|Module|ModuleName|Target|TargetModule))$",
    re.IGNORECASE,
)


def _blank_comment(match: re.Match[str]) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in match.group(0))


def _strip_comments(src: str) -> str:
    src = re.sub(r"//.*", _blank_comment, src)
    return re.sub(r"/\*.*?\*/", _blank_comment, src, flags=re.S)


def _clean_expr(expr: str) -> str:
    return expr.strip().strip("&*").strip()


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


def _split_args(call_text: str) -> list[str]:
    start = call_text.find("(")
    end = call_text.rfind(")")
    if start < 0 or end <= start:
        return []
    args_text = call_text[start + 1:end]
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


def _is_dynamic_sink(expr: str) -> bool:
    expr = _clean_expr(expr)
    if not expr:
        return False
    if '"' in expr or "'" in expr:
        return False
    if _CONFIGURED_SINK_RE.search(expr):
        return False
    return bool(_DYNAMIC_SINK_RE.search(expr))


def _unchecked_reward_sink_reason(body_text: str) -> str | None:
    if _POLICY_GUARD_RE.search(body_text):
        return None

    for match in _SEND_CALL_RE.finditer(body_text):
        call = _balanced_call(body_text, match.end() - 1)
        if call is None:
            continue
        args = _split_args(call)
        name = match.group("name").lower()

        if name == "sendcoinsfrommoduletoaccount" and len(args) >= 4:
            if _is_dynamic_sink(args[2]):
                return "reward coins flow to an account recipient without blocked-address or module-account policy"

        if name == "sendcoinsfrommoduletomodule" and len(args) >= 4:
            if _is_dynamic_sink(args[2]):
                return "reward coins flow to a dynamic module account without an allowlist"

        if name not in {"sendcoinsfrommoduletoaccount", "sendcoinsfrommoduletomodule"}:
            if any(_is_dynamic_sink(arg) for arg in args[:3]):
                return "reward payout helper uses a dynamic sink without recipient policy"

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
        body_text = _strip_comments(engine.text(body))
        if not _REWARD_CONTEXT_RE.search(name + "\n" + fn_text):
            continue

        reason = _unchecked_reward_sink_reason(body_text)
        if reason is None:
            continue

        hits.append({
            "severity": "high",
            "line": engine.line(fn),
            "col": engine.col(fn),
            "snippet": fn_text.splitlines()[0][:160],
            "message": (
                f"`{name}` has a rewards-distribution-skew sink policy gap: "
                f"{reason}. Reward distribution paths should bind payout "
                f"sinks to allowed module accounts or reject blocked/module "
                f"recipients before moving funds. "
                f"(class: rewards-distribution-skew)"
            ),
        })
    return hits

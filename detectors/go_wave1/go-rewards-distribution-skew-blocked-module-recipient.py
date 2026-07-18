"""
go-rewards-distribution-skew-blocked-module-recipient.py

Detects Go/Cosmos reward and distribution flows where reward value can be
routed to a blocked address, an unexpected module account, or a module account
whose funded coins can drift below the recorded reward entitlement.

This is intentionally narrower than the generic blocked-address transfer
detector. It requires reward/distribution context plus a value-moving Cosmos
bank sink. The Evmos seed is the module-account blocked-recipient invariant:
module accounts such as distribution, mint, and fee collector must only receive
coins through their intended module pipeline. The Allora reward-skew sibling
adds the reward-specific accounting variant: full-precision reward shares are
recorded while rounded coins are sent to the pending-reward module account.
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.go-rewards-distribution-skew-blocked-module-recipient"

_REWARD_NAME_RE = re.compile(
    r"(Reward|Rewards|Distribute|Distribution|Delegator|Validator|Emission"
    r"|Commission|Incentive|Allocate|Payout|Claim|Withdraw)",
    re.IGNORECASE,
)

_REWARD_BODY_RE = re.compile(
    r"(Reward|Rewards|Distribution|DelegatorReward|RewardPerShare"
    r"|OutstandingRewards|PendingReward|FeeCollector|CommunityPool"
    r"|AlloraPendingReward|ModuleAccount|AccountName)",
    re.IGNORECASE,
)

_MODULE_TO_ACCOUNT_RE = re.compile(
    r"\bSendCoinsFromModuleToAccount\s*\(\s*[^,\n]+,\s*"
    r"(?P<from>[^,\n]+)\s*,\s*(?P<to>[^,\n]+)",
    re.IGNORECASE,
)

_MODULE_TO_MODULE_RE = re.compile(
    r"\bSendCoinsFromModuleToModule\s*\(\s*[^,\n]+,\s*"
    r"(?P<from>[^,\n]+)\s*,\s*(?P<to>[^,\n]+)",
    re.IGNORECASE,
)

_OTHER_REWARD_SINK_RE = re.compile(
    r"(\bFundCommunityPool\s*\(|\bDistributeFromFeePool\s*\("
    r"|\bAllocateTokens\s*\(|\bWithdrawDelegatorReward\s*\()",
    re.IGNORECASE,
)

_BANK_MSGSEND_NAME_RE = re.compile(
    r"^(MsgSend|SendCoins|handleMsgSend|InputOutputCoins)$",
    re.IGNORECASE,
)

_BANK_SEND_TOADDR_RE = re.compile(
    r"\bSendCoins\s*\(\s*[^,\n]+,\s*[^,\n]+,\s*"
    r"(?:toAddr|msg\.ToAddress|recipient)\b",
    re.IGNORECASE,
)

_BANK_DEBIT_RE = re.compile(
    r"(subUnlockedCoins\s*\(|SubtractCoins\s*\(|sendCoins\s*\()",
    re.IGNORECASE,
)

_BLOCKED_OR_RECIPIENT_GUARD_RE = re.compile(
    r"(BlockedAddr\s*\(|IsBlockedAddr\s*\(|blockedAddrs\s*\["
    r"|BlockedAddress|IsSanctioned\s*\(|IsFrozen\s*\(|FrozenAddr\s*\("
    r"|ValidateRewardRecipient\s*\(|ValidateRecipient\s*\("
    r"|ValidateModuleAccountRecipient\s*\(|ExpectedReceivable\s*\("
    r"|IsModuleAccount\s*\(|GetModuleAccount\s*\(|GetModuleAddress\s*\("
    r"|AllowedRewardRecipient|IsAllowedRewardRecipient)",
    re.IGNORECASE,
)

_MODULE_POLICY_GUARD_RE = re.compile(
    r"(AllowedRewardModule|IsAllowedRewardModule|ValidateRewardModule"
    r"|ExpectedRewardModule|AllowedModuleAccount|ReceivableModule"
    r"|expectedReceivable|ModuleAccountAddrs|AllowedModule"
    r"|if\s+[^{}\n]*(?:toModule|targetModule|recipientModule|moduleName)"
    r"[^{}\n]*(?:==|!=)[^{}\n]*(?:Reward|Distribution|FeeCollector"
    r"|CommunityPool|PendingReward))",
    re.IGNORECASE,
)

_DYNAMIC_MODULE_TARGET_RE = re.compile(
    r"(^|\b)(msg\.[A-Za-z_]\w*|[A-Za-z_]\w*(?:Module|Account|Recipient|Name))$",
    re.IGNORECASE,
)

_REWARD_ACCOUNTING_RE = re.compile(
    r"(Set[A-Za-z]*Reward[A-Za-z]*\s*\(|SetDelegateRewardPerShare\s*\("
    r"|RewardPerShare|OutstandingRewards|DelegatorStartingInfo"
    r"|IncrementReward|Set[A-Za-z]*Commission\s*\()",
    re.IGNORECASE,
)

_ROUNDING_RE = re.compile(
    r"(SdkIntTrim\s*\(|TruncateInt\s*\(|RoundInt\s*\(|QuoTruncate\s*\("
    r"|QuoInt\s*\(|SafeInt64\s*\(|\.Int64\s*\()",
    re.IGNORECASE,
)

_ROUNDING_ALIGNMENT_GUARD_RE = re.compile(
    r"(truncatedReward|roundedReward|rewardCoins|coinsForShare"
    r"|shareFromCoins|rewardInt|fundedReward)",
    re.IGNORECASE,
)


def _blank_comment(match: re.Match[str]) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in match.group(0))


def _strip_comments(src: str) -> str:
    src = re.sub(r"//.*", _blank_comment, src)
    return re.sub(r"/\*.*?\*/", _blank_comment, src, flags=re.S)


def _clean_expr(expr: str) -> str:
    return expr.strip().strip("&*").strip()


def _is_dynamic_module_target(expr: str) -> bool:
    expr = _clean_expr(expr)
    if expr.startswith(("types.", "authtypes.", "distrtypes.", "minttypes.")):
        return False
    if '"' in expr or "'" in expr:
        return False
    return bool(_DYNAMIC_MODULE_TARGET_RE.search(expr))


def _has_reward_context(name: str, fn_text: str, body_text: str) -> bool:
    if _REWARD_NAME_RE.search(name):
        return True
    if _REWARD_BODY_RE.search(body_text):
        return True
    return bool(_REWARD_BODY_RE.search(fn_text))


def _module_to_account_reason(body_text: str) -> str | None:
    if not _MODULE_TO_ACCOUNT_RE.search(body_text):
        return None
    if _BLOCKED_OR_RECIPIENT_GUARD_RE.search(body_text):
        return None
    return "reward value is sent to an account recipient without blocked-address or module-account validation"


def _module_to_module_reason(body_text: str) -> str | None:
    for match in _MODULE_TO_MODULE_RE.finditer(body_text):
        target = _clean_expr(match.group("to"))
        if _is_dynamic_module_target(target) and not _MODULE_POLICY_GUARD_RE.search(body_text):
            return "reward value is sent to a dynamic module-account target without an allowlist"
    return None


def _rounding_skew_reason(body_text: str) -> str | None:
    if not _MODULE_TO_MODULE_RE.search(body_text):
        return None
    if not _REWARD_ACCOUNTING_RE.search(body_text):
        return None
    if not _ROUNDING_RE.search(body_text):
        return None
    if _ROUNDING_ALIGNMENT_GUARD_RE.search(body_text):
        return None
    return "reward entitlement accounting is updated while module funding uses a rounded amount"


def _other_sink_reason(body_text: str) -> str | None:
    if not _OTHER_REWARD_SINK_RE.search(body_text):
        return None
    if _BLOCKED_OR_RECIPIENT_GUARD_RE.search(body_text) or _MODULE_POLICY_GUARD_RE.search(body_text):
        return None
    return "distribution sink executes without recipient or module-account policy checks"


def _bank_msgsend_seed_reason(name: str, body_text: str, filepath: str) -> str | None:
    path = filepath.replace("\\", "/").lower()
    if "/x/bank/" not in path and not path.endswith("/bank/keeper.go"):
        return None
    if not _BANK_MSGSEND_NAME_RE.match(name):
        return None
    if not _BANK_SEND_TOADDR_RE.search(body_text):
        return None
    if not _BANK_DEBIT_RE.search(body_text):
        return None
    if _BLOCKED_OR_RECIPIENT_GUARD_RE.search(body_text):
        return None
    return "bank send path can route coins to blocked module-account recipients such as distribution or fee collector"


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
        seed_reason = _bank_msgsend_seed_reason(name, body_text, filepath)
        if seed_reason is None and not _has_reward_context(name, fn_text, body_text):
            continue

        reason = (
            seed_reason
            or _module_to_account_reason(body_text)
            or _module_to_module_reason(body_text)
            or _rounding_skew_reason(body_text)
            or _other_sink_reason(body_text)
        )
        if reason is None:
            continue

        hits.append({
            "severity": "high",
            "line": engine.line(fn),
            "col": engine.col(fn),
            "snippet": fn_text.splitlines()[0][:160],
            "message": (
                f"`{name}` has a rewards-distribution-skew routing gap: "
                f"{reason}. Reward/distribution flows should reject blocked "
                f"module recipients, constrain module-account targets, and "
                f"align recorded reward entitlements with funded module "
                f"balances. (class: rewards-distribution-skew)"
            ),
        })
    return hits

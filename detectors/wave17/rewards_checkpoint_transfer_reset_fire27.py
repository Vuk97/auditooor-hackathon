"""
rewards-checkpoint-transfer-reset-fire27

Solidity same-class recall detector for rewards-distribution-skew misses where
an NFT, staking, or voting transfer hook clears reward, delegate, checkpoint,
epoch cursor, or accrued state instead of settling both sides and preserving
history.

Confirmed sources:
- reference/patterns.dsl/checkpoints-cleared-on-nft-transfer.yaml
- reference/patterns.dsl/branch-asymmetric-idempotency-flag-toggled-in-only-one-arm.yaml
- reference/patterns.dsl/delegate-grief-unbounded-recipients.yaml

Detector hits are candidate evidence only. They do not prove exploitability or
filing readiness without a real protocol path, impact proof, and negative
control.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "rewards-checkpoint-transfer-reset-fire27"
DETECTOR_SEVERITY_DEFAULT = "Medium"


@dataclass
class Finding:
    detector: str
    file: str
    line: int
    severity: str
    message: str
    function: Optional[str] = None


@dataclass
class FunctionSlice:
    name: str
    header: str
    body: str
    body_line: int


_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_TOKEN_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)

_TRANSFER_HOOK_NAME_RE = re.compile(
    r"^(?:"
    r"_?beforeTokenTransfer|_?afterTokenTransfer|_update|_transfer|"
    r"transferFrom|safeTransferFrom|onTransfer|beforeTransfer|afterTransfer|"
    r"_?transferStake|transferStake|_?moveStake|_?transferVotingPower|"
    r"_?transferVotingUnits|_?moveVotingPower|_?moveDelegates?|"
    r"_?moveDelegateVotes"
    r")$",
    re.IGNORECASE,
)
_TRANSFER_CONTEXT_RE = re.compile(
    r"\b(?:from|sender|srcRep|srcDelegate|owner|oldOwner)\b[\s\S]{0,180}"
    r"\b(?:to|recipient|receiver|dstRep|dstDelegate|newOwner)\b|"
    r"\b(?:tokenId|tokenIds|stakeId|positionId|delegat(?:e|ion)|votingPower|"
    r"votingUnits|checkpoint|reward)\b",
    re.IGNORECASE,
)

_STATE_CONTEXT_RE = re.compile(
    r"(?:reward|Reward|checkpoint|Checkpoint|delegate|Delegate|delegation|"
    r"Delegation|votes|Votes|votingPower|VotingPower|epoch|Epoch|cursor|"
    r"Cursor|accrued|Accrued|pending|Pending|claimable|Claimable|earned|"
    r"Earned|rewardDebt|RewardDebt|userRewardPerTokenPaid|lastClaimed|"
    r"LastClaimed)",
    re.IGNORECASE,
)

_STATE_SLOT = (
    r"(?:[A-Za-z_][A-Za-z0-9_]*\.)?"
    r"(?:"
    r"_?checkpoints?|voteCheckpoints?|delegateCheckpoints?|"
    r"delegationCheckpoints?|rewardCheckpoints?|"
    r"[A-Za-z_][A-Za-z0-9_]*(?:Checkpoint|Checkpoints|checkpoint|checkpoints)"
    r"[A-Za-z0-9_]*|"
    r"epochCursor|rewardEpochCursor|lastClaimedEpoch|lastRewardEpoch|"
    r"[A-Za-z_][A-Za-z0-9_]*(?:EpochCursor|epochCursor|Cursor|cursor)"
    r"[A-Za-z0-9_]*|"
    r"rewardDebt|rewardDebts|userRewardDebt|userRewardDebts|"
    r"userRewardPerTokenPaid|rewardIndexPaid|lastRewardIndex|"
    r"pendingRewards?|claimableRewards?|accruedRewards?|earnedRewards?|"
    r"unclaimedRewards?|rewardsAccrued|rewardBalances?|"
    r"[A-Za-z_][A-Za-z0-9_]*(?:RewardDebt|rewardDebt|RewardIndex|"
    r"rewardIndex|RewardPerTokenPaid|rewardPerTokenPaid|PendingReward|"
    r"pendingReward|ClaimableReward|claimableReward|AccruedReward|"
    r"accruedReward|EarnedReward|earnedReward|UnclaimedReward|"
    r"unclaimedReward|RewardsAccrued|rewardsAccrued)"
    r"[A-Za-z0-9_]*|"
    r"delegateVotes|delegatedVotes|delegatedPower|"
    r"[A-Za-z_][A-Za-z0-9_]*(?:DelegateVotes|delegateVotes|"
    r"DelegatedVotes|delegatedVotes|DelegatedPower|delegatedPower)"
    r"[A-Za-z0-9_]*"
    r")"
)
_INDEXES = r"(?:\s*\[[^\]]+\]\s*)+"
_ZERO_OR_EMPTY_VALUE = (
    r"(?:0|uint256\s*\(\s*0\s*\)|false|\[\]|"
    r"new\s+[A-Za-z_][A-Za-z0-9_]*(?:\[\])+\s*\(\s*0?\s*\))"
)
_CURSOR_RESET_VALUE = (
    r"(?:currentEpoch|epoch|currentRound|round|period|block\.number|"
    r"rewardPerTokenStored|accRewardPerShare|globalRewardIndex|rewardIndex)"
)
_RESET_RE = re.compile(
    rf"\bdelete\s+(?P<delete_slot>{_STATE_SLOT}){_INDEXES}\s*;|"
    rf"\b(?P<assign_slot>{_STATE_SLOT}){_INDEXES}"
    rf"(?:\.\s*length\s*)?=\s*(?P<assign_value>{_ZERO_OR_EMPTY_VALUE})\s*;|"
    rf"\b(?P<cursor_slot>{_STATE_SLOT}){_INDEXES}\s*=\s*"
    rf"(?P<cursor_value>{_CURSOR_RESET_VALUE})\s*;",
    re.IGNORECASE | re.DOTALL,
)
_CHECKPOINT_SLOT_RE = re.compile(r"checkpoint|checkpoints|delegateVotes|delegatedVotes", re.IGNORECASE)
_REWARD_RESET_SLOT_RE = re.compile(
    r"reward|epoch|cursor|accrued|pending|claimable|earned|unclaimed|debt|"
    r"userRewardPerTokenPaid|lastClaimed",
    re.IGNORECASE,
)
_SETTLEMENT_CALL_RE = re.compile(
    r"\b(?:_?(?:settle|accrue|sync|update|checkpoint|record|write|claim|"
    r"harvest)[A-Za-z0-9_]*(?:Reward|Rewards|Accrual|Checkpoint|"
    r"Checkpoints|Delegate|Delegates|Votes|Cursor)?|"
    r"_?updateRewards?|_?settleRewards?|_?accrueRewards?|"
    r"_?writeCheckpoint|_?writeDelegateCheckpoint|_?checkpointDelegate)"
    r"\s*\((?P<args>[^;{}]*)\)",
    re.IGNORECASE | re.DOTALL,
)
_SYMMETRIC_SETTLEMENT_HINT_RE = re.compile(
    r"\b(?:settleBothSides|settleTransferRewards|checkpointBothSides|"
    r"settleSenderAndReceiver|_settleTransfer)\s*\(",
    re.IGNORECASE,
)

_SENDER_ALIASES = (
    "from",
    "sender",
    "src",
    "srcRep",
    "srcDelegate",
    "owner",
    "oldOwner",
)
_RECEIVER_ALIASES = (
    "to",
    "recipient",
    "receiver",
    "dst",
    "dstRep",
    "dstDelegate",
    "newOwner",
)


def _strip_comments_and_strings(source: str) -> str:
    def replace_token(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _TOKEN_RE.sub(replace_token, source or "")


def _find_matching_delimiter(source: str, open_pos: int, open_char: str, close_char: str) -> int:
    if open_pos < 0 or open_pos >= len(source) or source[open_pos] != open_char:
        return -1
    depth = 1
    i = open_pos + 1
    while i < len(source) and depth > 0:
        char = source[i]
        if char == open_char:
            depth += 1
        elif char == close_char:
            depth -= 1
        i += 1
    return i - 1 if depth == 0 else -1


def _extract_balanced_block(source: str, open_brace: int) -> tuple[Optional[str], int]:
    close_brace = _find_matching_delimiter(source, open_brace, "{", "}")
    if close_brace < 0:
        return None, open_brace
    return source[open_brace + 1:close_brace], close_brace + 1


def _split_functions(source: str) -> list[FunctionSlice]:
    out: list[FunctionSlice] = []
    pos = 0
    while True:
        match = _FN_HEADER_RE.search(source, pos)
        if match is None:
            break
        name = match.group("name")
        open_paren = source.find("(", match.end() - 1)
        close_paren = _find_matching_delimiter(source, open_paren, "(", ")")
        if close_paren < 0:
            pos = match.end()
            continue

        body_start = -1
        j = close_paren + 1
        while j < len(source):
            if source[j] == ";":
                break
            if source[j] == "{":
                body_start = j
                break
            j += 1
        if body_start < 0:
            pos = max(j, close_paren + 1)
            continue

        body, end_pos = _extract_balanced_block(source, body_start)
        if body is None:
            pos = body_start + 1
            continue

        header = source[match.start():body_start]
        body_line = source.count("\n", 0, body_start + 1) + 1
        out.append(FunctionSlice(name=name, header=header, body=body, body_line=body_line))
        pos = end_pos
    return out


def _line_for_match(fn: FunctionSlice, match: re.Match[str]) -> int:
    return fn.body_line + fn.body.count("\n", 0, match.start())


def _slot_name(match: re.Match[str]) -> str:
    return (
        match.groupdict().get("delete_slot")
        or match.groupdict().get("assign_slot")
        or match.groupdict().get("cursor_slot")
        or "checkpoint_or_reward_state"
    )


def _reset_verb(match: re.Match[str]) -> str:
    if match.groupdict().get("delete_slot"):
        return "delete"
    value = match.groupdict().get("assign_value")
    if value is not None:
        if re.search(r"\[\]|new\s+[A-Za-z_][A-Za-z0-9_]*(?:\[\])+", value):
            return "empty-array reset"
        return "zero" if re.search(r"\b0\b|false", value, re.IGNORECASE) else "empty reset"
    return "cursor/index reset"


def _is_transfer_surface(fn: FunctionSlice) -> bool:
    if not _TRANSFER_HOOK_NAME_RE.search(fn.name):
        return False
    text = f"{fn.header}\n{fn.body[:1200]}"
    return bool(_TRANSFER_CONTEXT_RE.search(text))


def _call_args_contain_alias(args: str, aliases: tuple[str, ...]) -> bool:
    for alias in aliases:
        if re.search(rf"\b{re.escape(alias)}\b", args):
            return True
    return False


def _has_settlement_for_both_sides(text: str) -> bool:
    if _SYMMETRIC_SETTLEMENT_HINT_RE.search(text):
        return True

    sender_seen = False
    receiver_seen = False
    for call in _SETTLEMENT_CALL_RE.finditer(text):
        args = call.group("args")
        sender_seen = sender_seen or _call_args_contain_alias(args, _SENDER_ALIASES)
        receiver_seen = receiver_seen or _call_args_contain_alias(args, _RECEIVER_ALIASES)
        if sender_seen and receiver_seen:
            return True
    return False


def _should_report_reset(fn: FunctionSlice, match: re.Match[str]) -> tuple[bool, str]:
    slot = _slot_name(match)
    verb = _reset_verb(match)
    prefix = f"{fn.header}\n{fn.body[:match.start()]}"

    if _CHECKPOINT_SLOT_RE.search(slot):
        return True, (
            f"{verb}s `{slot}` in a transfer hook; checkpoint history should "
            "be appended or settled, not cleared"
        )

    if _REWARD_RESET_SLOT_RE.search(slot) and _has_settlement_for_both_sides(prefix):
        return False, ""

    return True, (
        f"{verb}s `{slot}` in a transfer hook before reward settlement is "
        "visible for both sender and receiver"
    )


def _checkpoint_transfer_reset(fn: FunctionSlice) -> tuple[re.Match[str], str] | None:
    if not _is_transfer_surface(fn):
        return None
    if not _STATE_CONTEXT_RE.search(fn.body):
        return None

    for reset in _RESET_RE.finditer(fn.body):
        should_report, reason = _should_report_reset(fn, reset)
        if should_report:
            return reset, reason
    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    clean = _strip_comments_and_strings(source)
    if not _STATE_CONTEXT_RE.search(clean):
        return []

    findings: list[Finding] = []
    for fn in _split_functions(clean):
        result = _checkpoint_transfer_reset(fn)
        if result is None:
            continue
        match, reason = result
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=_line_for_match(fn, match),
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn.name,
                message=(
                    f"`{fn.name}` has rewards checkpoint transfer reset: "
                    f"{reason}. Transfer hooks must settle or checkpoint "
                    "sender and receiver reward state before balance, owner, "
                    "or delegate movement, and must preserve historical "
                    "checkpoint arrays."
                ),
            )
        )
    return findings


__all__ = [
    "DETECTOR_NAME",
    "DETECTOR_SEVERITY_DEFAULT",
    "Finding",
    "scan",
]

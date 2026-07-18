"""
rewards-branch-asymmetry-fire38

Solidity same-class recall detector for rewards-distribution-skew misses where
one branch records withdrawn, claimed, checkpointed, processed, or similar
one-shot state while a sibling branch distributes rewards, recipient lists, or
delegation effects without the same checkpoint or status update.

Seeded from:
- reports/detector_lift_fire37_20260605/post_priorities_solidity.md
- detectors/wave17/rewards_distribution_skew_missing_checkpoint_before_weight_change.py
- reference/patterns.dsl/rewardloss-in-staking-contracts.yaml
- branch-asymmetric-idempotency-flag-toggled-in-only-one-arm
- delegate-grief-unbounded-recipients

Detector hits are candidate evidence only. They do not prove exploitability or
filing readiness without a real protocol path, impact proof, and negative
control.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "rewards-branch-asymmetry-fire38"
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


@dataclass
class BranchPair:
    if_condition: str
    if_body: str
    if_start: int
    else_condition: str
    else_body: str
    else_start: int
    end: int


_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_PUBLIC_HEADER_RE = re.compile(r"\b(?:external|public)\b")
_TOKEN_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)

_SURFACE_CONTEXT_RE = re.compile(
    r"\b(?:reward\w*|claim\w*|withdraw\w*|settle\w*|release\w*|"
    r"distribut\w*|checkpoint\w*|processed|recipient\w*|receiver\w*|"
    r"delegat\w*|referr\w*|beneficiar\w*|payee\w*|payout\w*|"
    r"emission\w*|incentive\w*|claimable\w*|earned\w*|pending\w*)\b",
    re.IGNORECASE,
)
_BRANCH_CONTEXT_RE = re.compile(
    r"(?:direct|queued?|deferred|manual|fallback|delegat\w*|recipient\w*|"
    r"claim\w*|reward\w*|checkpoint\w*|processed|withdraw\w*|"
    r"distribut\w*|referr\w*|emission\w*|success|fail\w*|settle\w*|"
    r"release\w*|payout\w*)",
    re.IGNORECASE,
)

_STATUS_WORD_RE = (
    r"withdrawn|claimed|processed|consumed|redeemed|paid|settled|"
    r"released|unlocked|checkpointed|checkpoint|finalized|distributed|"
    r"reward[A-Za-z0-9_]*index|index[A-Za-z0-9_]*reward|last[A-Za-z0-9_]*update"
)
_STATUS_UPDATE_RE = re.compile(
    rf"\b(?=[A-Za-z_][A-Za-z0-9_]*\b)(?=[A-Za-z0-9_]*(?:{_STATUS_WORD_RE}))"
    r"[A-Za-z_][A-Za-z0-9_]*\b\s*(?:\[[^\]]+\]\s*)*"
    r"(?:\.\s*(?:status|index|timestamp|value|number)\s*)?"
    r"(?:=|\+=|-=)\s*[^;]+;|"
    r"\b_?(?:mark|set|toggle|checkpoint|settle|record|finalize|"
    r"consume|process|update)[A-Za-z0-9_]*(?:Withdrawn|Claimed|"
    r"Processed|Checkpoint|Checkpointed|Status|Paid|Settled|"
    r"Released|Unlocked|Distributed|Finalized|RewardIndex|LastUpdate)"
    r"[A-Za-z0-9_]*\s*\(",
    re.IGNORECASE | re.DOTALL,
)

_REWARD_OR_DELEGATE_EFFECT_RE = re.compile(
    r"\b(?:safeTransfer|safeTransferFrom|safeTransferETH|safeNativeTransfer|"
    r"sendValue|transfer|send|mint|_mint|claimReward|payReward|"
    r"creditReward|releaseReward|unlockReward|distributeReward|"
    r"_payReward|_creditReward|_recordReward|_distributeReward|"
    r"_moveDelegates?|_delegate|_redelegate|_creditReferral|"
    r"_recordReferral)\s*\(|"
    r"\bpayable\s*\([^)]*(?:msg\.sender|user|recipient|receiver|"
    r"account|delegatee)[^)]*\)\s*\.\s*(?:transfer|send)\s*\(|"
    r"\.\s*call\s*\{\s*value\s*:|"
    r"\b(?:pendingRewards?|claimableRewards?|accruedRewards?|earnedRewards?|"
    r"unclaimedRewards?|rewardBalances?|rewardDebt|rewardDebts|"
    r"recipientRewards?|referralRewards?|referrerRewards?|"
    r"delegateReward\w*|delegatedReward\w*|rewardWeight\w*|"
    r"rewardRecipients?|delegateRewardRecipients?|rewardReceivers?|"
    r"rewardPayees?|rewardBeneficiaries?)\s*(?:\[[^\]]+\]\s*)+"
    r"(?:=|\+=|-=|\.\s*(?:push|add|remove)\s*\()",
    re.IGNORECASE | re.DOTALL,
)
_RECIPIENT_LIST_EFFECT_RE = re.compile(
    r"\b(?:recipients?|receivers?|beneficiaries|payees|delegates?|"
    r"delegatees|delegators|referrals?|referees|rewardRecipients?|"
    r"delegateRewardRecipients?)\s*(?:\[[^\]]+\]\s*)*"
    r"\.\s*(?:push|add|remove)\s*\(",
    re.IGNORECASE | re.DOTALL,
)
_COMMON_FINALIZER_CALL_RE = re.compile(
    r"\b(?P<name>_?(?:finalize|complete|finish|settle|checkpoint|record|"
    r"mark|consume|close|process)[A-Za-z0-9_]*|"
    r"_?update[A-Za-z0-9_]*(?:Reward|Rewards|Index|Checkpoint|Status|"
    r"LastUpdate)[A-Za-z0-9_]*)\s*\(",
    re.IGNORECASE,
)
_SYMMETRIC_HINT_RE = re.compile(
    r"\b(?:markAllBranchesProcessed|checkpointBothBranches|"
    r"settleBothRewardBranches|commonRewardFinalize|finalizeBothBranches|"
    r"_commonSettlementFinalizer|_finalizeRewardBranch|"
    r"_markCampaignProcessed)\s*\(",
    re.IGNORECASE,
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


def _skip_ws(source: str, pos: int) -> int:
    while pos < len(source) and source[pos].isspace():
        pos += 1
    return pos


def _read_condition(source: str, pos: int) -> tuple[Optional[str], int]:
    pos = _skip_ws(source, pos)
    if pos >= len(source) or source[pos] != "(":
        return None, pos
    close = _find_matching_delimiter(source, pos, "(", ")")
    if close < 0:
        return None, pos
    return source[pos + 1:close], close + 1


def _branch_pairs(body: str) -> list[BranchPair]:
    pairs: list[BranchPair] = []
    pos = 0
    while True:
        if_match = re.search(r"\bif\s*\(", body[pos:])
        if if_match is None:
            break
        if_start = pos + if_match.start()
        cond_start = body.find("(", if_start)
        if_condition, after_condition = _read_condition(body, cond_start)
        if if_condition is None:
            pos = if_start + 2
            continue

        if_block_start = _skip_ws(body, after_condition)
        if if_block_start >= len(body) or body[if_block_start] != "{":
            pos = if_start + 2
            continue
        if_body, after_if = _extract_balanced_block(body, if_block_start)
        if if_body is None:
            pos = if_start + 2
            continue

        else_pos = _skip_ws(body, after_if)
        if not body.startswith("else", else_pos):
            pos = after_if
            continue

        else_condition = "else"
        after_else = _skip_ws(body, else_pos + len("else"))
        if body.startswith("if", after_else) and (
            after_else + 2 == len(body) or not body[after_else + 2].isalnum()
        ):
            else_condition, after_else = _read_condition(body, after_else + 2)
            if else_condition is None:
                pos = after_if
                continue

        else_block_start = _skip_ws(body, after_else)
        if else_block_start >= len(body) or body[else_block_start] != "{":
            pos = after_if
            continue
        else_body, after_else_block = _extract_balanced_block(body, else_block_start)
        if else_body is None:
            pos = after_if
            continue

        pairs.append(
            BranchPair(
                if_condition=if_condition,
                if_body=if_body,
                if_start=if_start,
                else_condition=else_condition,
                else_body=else_body,
                else_start=else_pos,
                end=after_else_block,
            )
        )
        pos = after_if
    return pairs


def _line_for_offset(fn: FunctionSlice, offset: int) -> int:
    return fn.body_line + fn.body.count("\n", 0, max(0, offset))


def _has_effect(branch: str) -> bool:
    return bool(
        _REWARD_OR_DELEGATE_EFFECT_RE.search(branch)
        or _RECIPIENT_LIST_EFFECT_RE.search(branch)
    )


def _common_finalizer_names(left: str, right: str) -> set[str]:
    left_names = {match.group("name").lower() for match in _COMMON_FINALIZER_CALL_RE.finditer(left)}
    right_names = {match.group("name").lower() for match in _COMMON_FINALIZER_CALL_RE.finditer(right)}
    return left_names & right_names


def _has_common_post_branch_status(fn: FunctionSlice, pair: BranchPair) -> bool:
    tail = fn.body[pair.end:pair.end + 1600]
    return bool(_STATUS_UPDATE_RE.search(tail) or _COMMON_FINALIZER_CALL_RE.search(tail))


def _has_reward_delegate_surface(fn: FunctionSlice, pair: BranchPair) -> bool:
    text = "\n".join(
        (
            fn.name,
            fn.header,
            pair.if_condition,
            pair.else_condition,
            pair.if_body[:900],
            pair.else_body[:900],
        )
    )
    return bool(_SURFACE_CONTEXT_RE.search(text) and _BRANCH_CONTEXT_RE.search(text))


def _branch_asymmetry(fn: FunctionSlice) -> tuple[int, str] | None:
    if not _PUBLIC_HEADER_RE.search(fn.header):
        return None
    if _SYMMETRIC_HINT_RE.search(fn.body):
        return None

    for pair in _branch_pairs(fn.body):
        if not _has_reward_delegate_surface(fn, pair):
            continue
        if _common_finalizer_names(pair.if_body, pair.else_body):
            continue
        if _has_common_post_branch_status(fn, pair):
            continue

        if_status = _STATUS_UPDATE_RE.search(pair.if_body)
        else_status = _STATUS_UPDATE_RE.search(pair.else_body)
        if bool(if_status) == bool(else_status):
            continue

        if_effect = _has_effect(pair.if_body)
        else_effect = _has_effect(pair.else_body)

        if if_status is None and if_effect:
            return (
                pair.if_start,
                "if branch distributes reward, recipient, or delegation effects "
                "without the status or checkpoint update present in the sibling branch",
            )
        if else_status is None and else_effect:
            return (
                pair.else_start,
                "else branch distributes reward, recipient, or delegation effects "
                "without the status or checkpoint update present in the sibling branch",
            )
    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    clean = _strip_comments_and_strings(source)
    if not _SURFACE_CONTEXT_RE.search(clean):
        return []

    findings: list[Finding] = []
    for fn in _split_functions(clean):
        result = _branch_asymmetry(fn)
        if result is None:
            continue
        offset, reason = result
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=_line_for_offset(fn, offset),
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn.name,
                message=(
                    f"`{fn.name}` has rewards branch status asymmetry: "
                    f"{reason}. Reward distribution, recipient-list, and "
                    "delegation-effect branches should consume the same "
                    "withdrawn, claimed, checkpointed, or processed state in "
                    "every effectful arm, or in shared code after the branch."
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

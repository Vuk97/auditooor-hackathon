"""
rewards-post-mutation-checkpoint-fire29

Solidity same-class recall detector for rewards-distribution-skew misses where
a user balance, stake amount, or NFT owner mapping is changed before pending
rewards, reward debt, or user reward-index state is checkpointed.

Confirmed sources:
- reference/patterns.dsl/staking-reward-missing-checkpoint-on-transfer.yaml
- reference/patterns.dsl/reward-pool-reward-integral-manipulable.yaml
- reference/patterns.dsl.zellic_k2_mined/manual-reward-claims-use-stale-accrued-balances.yaml

Detector hits are candidate evidence only. They do not prove exploitability or
filing readiness without a real protocol path, impact proof, and negative
control.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "rewards-post-mutation-checkpoint-fire29"
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

_REWARD_CONTEXT_RE = re.compile(
    r"(?:reward|rewards|Reward|Rewards|rewardDebt|userRewardDebt|"
    r"userRewardPerTokenPaid|rewardPerToken|accRewardPerShare|rewardIndex|"
    r"integral|pendingRewards?|claimableRewards?|accruedRewards?|"
    r"earnedRewards?|unclaimedRewards?|checkpoint|Checkpoint)",
    re.IGNORECASE,
)
_MUTATION_CONTEXT_RE = re.compile(
    r"(?:transfer|stake|unstake|withdraw|deposit|mint|burn|move|owner|"
    r"tokenId|position|balance|shares?)",
    re.IGNORECASE,
)

_INDEXES = r"(?:\s*\[[^\]]+\]\s*)+"
_USER_BALANCE_SLOT = (
    r"(?:"
    r"_?balances|balanceOf|balances|stakedBalance|stakingBalance|stakeOf|"
    r"stakes|userStake|userStakes|stakeInfo|userInfo|deposits|depositInfo|"
    r"shares|userShares|memberShares|poolShares|weights|userWeights|amounts"
    r")"
)
_NFT_OWNER_SLOT = (
    r"(?:"
    r"_?owners|ownerOf|tokenOwner|tokenOwners|positionOwner|positionOwners|"
    r"nftOwner|nftOwners|stakeOwner|stakeOwners"
    r")"
)
_MAPPED_BALANCE_MUTATION_RE = re.compile(
    rf"\b(?P<slot>{_USER_BALANCE_SLOT}){_INDEXES}"
    rf"(?:\.\s*(?:amount|balance|balances|shares|stake|staked|weight))?"
    rf"\s*(?P<op>\+=|-=|=|\+\+|--)",
    re.IGNORECASE | re.DOTALL,
)
_NFT_OWNER_MUTATION_RE = re.compile(
    rf"\b(?P<slot>{_NFT_OWNER_SLOT}){_INDEXES}"
    rf"(?:\.\s*(?:owner|holder))?\s*=\s*"
    rf"(?P<value>[A-Za-z_][A-Za-z0-9_\.]*)\s*;",
    re.IGNORECASE | re.DOTALL,
)
_POSITION_OWNER_MUTATION_RE = re.compile(
    r"\b(?P<slot>(?:positions|positionInfo|lockedNfts|stakes|stakeInfo)"
    r"\s*(?:\[[^\]]+\]\s*)+)\.\s*(?:owner|holder)\s*=\s*"
    r"(?P<value>[A-Za-z_][A-Za-z0-9_\.]*)\s*;",
    re.IGNORECASE | re.DOTALL,
)
_MUTATION_CALL_RE = re.compile(
    r"\b(?P<slot>_?(?:transferStake|moveStake|moveShares|movePosition|"
    r"transferPosition|transferPositionNft|transferRewardShare|transferVotingUnits))"
    r"\s*\(",
    re.IGNORECASE,
)

_CHECKPOINT_CALL_RE = re.compile(
    r"\b(?:"
    r"_?updateRewards?|_?updateReward|_?checkpointRewards?|_?checkpointReward|"
    r"_?checkpointUser|_?checkpointAccount|_?checkpointPosition|"
    r"_?settleRewards?|_?settleReward|_?settlePositionRewards?|"
    r"_?accrueRewards?|_?accrueReward|_?harvestRewards?|_?harvestReward|"
    r"_?claimRewards?|_?claimReward|_?updatePool|_?updateRewardIndex|"
    r"update_asset_reward_index|calculate_user_accrued_rewards|handle_action"
    r")\s*\(",
    re.IGNORECASE,
)
_REWARD_STATE_WRITE_RE = re.compile(
    r"\b(?P<slot>"
    r"pendingRewards?|claimableRewards?|accruedRewards?|earnedRewards?|"
    r"unclaimedRewards?|cachedRewards?|userRewards?|rewards|rewardDebt|"
    r"rewardDebts|userRewardDebt|userRewardDebts|userRewardPerTokenPaid|"
    r"rewardIndexPaid|lastRewardIndex|rewardCheckpoint|lastClaimedRewardIndex"
    r")\s*(?:\[[^\]]+\]\s*)+(?:\.\s*[A-Za-z_][A-Za-z0-9_]*)?"
    r"\s*(?:\+=|-=|=)",
    re.IGNORECASE | re.DOTALL,
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
    return source[open_brace + 1 : close_brace], close_brace + 1


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

        header = source[match.start() : body_start]
        body_line = source.count("\n", 0, body_start + 1) + 1
        out.append(FunctionSlice(name=name, header=header, body=body, body_line=body_line))
        pos = end_pos
    return out


def _line_for_match(fn: FunctionSlice, match: re.Match[str]) -> int:
    return fn.body_line + fn.body.count("\n", 0, match.start())


def _first_match(regexes: tuple[re.Pattern[str], ...], text: str) -> re.Match[str] | None:
    matches = [match for regex in regexes if (match := regex.search(text)) is not None]
    if not matches:
        return None
    return min(matches, key=lambda match: match.start())


def _has_prior_checkpoint_or_settlement(text: str) -> bool:
    return bool(_CHECKPOINT_CALL_RE.search(text) or _REWARD_STATE_WRITE_RE.search(text))


def _late_checkpoint_or_reward_write(tail: str) -> re.Match[str] | None:
    return _first_match((_CHECKPOINT_CALL_RE, _REWARD_STATE_WRITE_RE), tail)


def _mutation_label(match: re.Match[str]) -> str:
    slot = match.groupdict().get("slot") or "user balance or owner state"
    if re.search(r"owner|position|nft", slot, re.IGNORECASE):
        return f"NFT or position owner state `{slot}`"
    if re.search(r"stake|staked|userInfo|deposit", slot, re.IGNORECASE):
        return f"stake state `{slot}`"
    if re.search(r"share|weight", slot, re.IGNORECASE):
        return f"reward weight state `{slot}`"
    return f"user balance state `{slot}`"


def _post_mutation_checkpoint(fn: FunctionSlice) -> tuple[re.Match[str], re.Match[str], str] | None:
    text = f"{fn.header}\n{fn.body}"
    if not _REWARD_CONTEXT_RE.search(text):
        return None
    if not (_MUTATION_CONTEXT_RE.search(fn.name) or _MUTATION_CONTEXT_RE.search(text)):
        return None

    mutation = _first_match(
        (
            _MAPPED_BALANCE_MUTATION_RE,
            _NFT_OWNER_MUTATION_RE,
            _POSITION_OWNER_MUTATION_RE,
            _MUTATION_CALL_RE,
        ),
        fn.body,
    )
    if mutation is None:
        return None

    prefix = f"{fn.header}\n{fn.body[:mutation.start()]}"
    if _has_prior_checkpoint_or_settlement(prefix):
        return None

    tail = fn.body[mutation.end() :]
    late_checkpoint = _late_checkpoint_or_reward_write(tail)
    if late_checkpoint is None:
        return None

    return mutation, late_checkpoint, _mutation_label(mutation)


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    clean = _strip_comments_and_strings(source)
    if not _REWARD_CONTEXT_RE.search(clean):
        return []

    findings: list[Finding] = []
    for fn in _split_functions(clean):
        result = _post_mutation_checkpoint(fn)
        if result is None:
            continue
        mutation, late_checkpoint, label = result
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=_line_for_match(fn, mutation),
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn.name,
                message=(
                    f"`{fn.name}` mutates {label} before reward settlement. "
                    "The first checkpoint or reward-debt write appears after "
                    f"the mutation near line {_line_for_match(fn, late_checkpoint)}. "
                    "Settle pending rewards and user reward indexes before "
                    "changing balance, stake, shares, or NFT ownership."
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

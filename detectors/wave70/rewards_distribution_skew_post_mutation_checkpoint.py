"""
rewards-distribution-skew-post-mutation-checkpoint

Conservative Solidity detector for reward-index skew where a balance or supply
mutation happens before the same function checkpoints the user's reward debt,
reward index, or accrued reward accumulator.

This complements older coverage that catches reward checkpoint omission or
stale denominator snapshots. The specific blindspot here is explicit bad order:

1. A deposit, withdraw, mint, burn, stake, or redeem path mutates balance-like
   or supply-like storage.
2. The same function later writes rewardDebt / userRewardIndex / accruedReward
   or calls an obvious reward checkpoint helper.
3. Because the checkpoint runs on post-mutation balances, rewards earned under
   the old balance are silently skewed or retired.

The detector stays conservative by requiring both:
- balance or supply state writes in the function, and
- reward checkpoint state writes or obvious checkpoint helper calls,
with the earliest balance mutation appearing before the earliest reward
checkpoint operation in source order.
"""

from __future__ import annotations

import re
import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

from slither.detectors.abstract_detector import (
    DETECTOR_INFO,
    AbstractDetector,
    DetectorClassification,
)
from slither.core.solidity_types import MappingType
from slither.utils.output import Output


_ENTRYPOINT_RE = re.compile(
    r"(?i)^(deposit|mint|stake|join|enter|increase|withdraw|redeem|burn|unstake|"
    r"exit|leave|transfer|transferFrom|claim|harvest|update)"
)
_BALANCE_VAR_RE = re.compile(
    r"(?i)("
    r"balanceOf|_balances|shares|poolShares|userShares|stakedBalance|stakeOf|"
    r"deposits|principal|receiptBalance|totalSupply|totalShares|totalStaked"
    r")"
)
_REWARD_VAR_RE = re.compile(
    r"(?i)("
    r"rewardDebt|userRewardIndex|accountRewardIndex|rewardIndexOf|"
    r"lastRewardIndex|rewardIntegral|claimableAmount|pendingRewards|"
    r"accruedRewards|accruedReward|rewardCheckpoint"
    r")"
)
_BALANCE_MUTATION_RE = re.compile(
    r"(?is)("
    r"(?:balanceOf|_balances|shares|poolShares|userShares|stakedBalance|stakeOf|"
    r"deposits|principal|receiptBalance|totalSupply|totalShares|totalStaked)"
    r"\s*(?:\[[^\]]+\])?\s*(?:\+=|-=|=)"
    r"|_mint\s*\(|_burn\s*\("
    r")"
)
_REWARD_CHECKPOINT_RE = re.compile(
    r"(?is)("
    r"(?:rewardDebt|userRewardIndex|accountRewardIndex|rewardIndexOf|"
    r"lastRewardIndex|rewardIntegral|claimableAmount|pendingRewards|"
    r"accruedRewards|accruedReward|rewardCheckpoint)"
    r"\s*(?:\[[^\]]+\])?\s*(?:\+=|-=|=)"
    r"|(?:_updateReward|updateReward|checkpointReward|checkpoint|"
    r"_checkpointClaimable|settleReward|accrueReward|syncReward)"
    r"\s*\("
    r")"
)
_SAFE_ORDER_RE = re.compile(
    r"(?is)("
    r"(?:rewardDebt|userRewardIndex|accountRewardIndex|rewardIndexOf|"
    r"lastRewardIndex|rewardIntegral|claimableAmount|pendingRewards|"
    r"accruedRewards|accruedReward|rewardCheckpoint)"
    r"\s*(?:\[[^\]]+\])?\s*(?:\+=|-=|=)"
    r"|(?:_updateReward|updateReward|checkpointReward|checkpoint|"
    r"_checkpointClaimable|settleReward|accrueReward|syncReward)"
    r"\s*\("
    r")[\s\S]{0,500}("
    r"(?:balanceOf|_balances|shares|poolShares|userShares|stakedBalance|stakeOf|"
    r"deposits|principal|receiptBalance|totalSupply|totalShares|totalStaked)"
    r"\s*(?:\[[^\]]+\])?\s*(?:\+=|-=|=)"
    r"|_mint\s*\(|_burn\s*\("
    r")"
)


def _source_of(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


def _is_candidate_reward_var(state_var) -> bool:
    name = getattr(state_var, "name", "") or ""
    if not name or not _REWARD_VAR_RE.search(name):
        return False
    return isinstance(getattr(state_var, "type", None), MappingType) or "reward" in name.lower()


def _is_candidate_balance_var(state_var) -> bool:
    name = getattr(state_var, "name", "") or ""
    return bool(name and _BALANCE_VAR_RE.search(name))


class RewardsDistributionSkewPostMutationCheckpoint(AbstractDetector):
    ARGUMENT = "rewards-distribution-skew-post-mutation-checkpoint"
    HELP = (
        "Balance or supply mutation happens before reward checkpointing, so "
        "reward debt or user index is updated against the post-mutation balance"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Reward checkpoint runs after balance mutation"
    WIKI_DESCRIPTION = (
        "Index-based reward systems usually require a per-user checkpoint before "
        "any balance or supply mutation. If a deposit, withdraw, mint, burn, or "
        "stake path first changes the user's balance and only then writes "
        "`rewardDebt`, `userRewardIndex`, `claimableAmount`, or a similar "
        "reward accumulator, the checkpoint no longer represents the user's old "
        "entitlement. Previously-earned rewards can be diluted, stranded, or "
        "shifted to a new balance regime."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "Alice has 100 shares while `accRewardPerShare` grows. She withdraws 40 "
        "shares. The withdraw path first subtracts `shares[msg.sender] -= 40` "
        "and only afterwards sets `rewardDebt[msg.sender] = shares[msg.sender] * "
        "accRewardPerShare / PRECISION`. The checkpoint now sees 60 shares "
        "instead of the pre-withdraw 100, so Alice loses rewards earned on the "
        "exited 40 shares."
    )
    WIKI_RECOMMENDATION = (
        "Checkpoint the user's reward state before mutating balances or supply. "
        "Prefer a single helper such as `_updateReward(account)` or "
        "`_checkpointClaimable(account)` as the first mutating step in every "
        "deposit, withdraw, mint, burn, stake, and redeem entrypoint."
    )

    SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
    COVERAGE_CLAIM = "detector_fixture_smoke_only"
    PROMOTION_ALLOWED = False

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue

            state_vars = list(getattr(contract, "state_variables", []) or [])
            reward_vars = {sv for sv in state_vars if _is_candidate_reward_var(sv)}
            balance_vars = {sv for sv in state_vars if _is_candidate_balance_var(sv)}
            if not reward_vars or not balance_vars:
                continue

            for function in getattr(contract, "functions_and_modifiers_declared", []) or []:
                if is_leaf_helper(function):
                    continue
                if getattr(function, "view", False) or getattr(function, "pure", False):
                    continue

                name = getattr(function, "name", "") or ""
                if not name or not _ENTRYPOINT_RE.search(name):
                    continue

                source = _source_of(function)
                if not source:
                    continue
                if re.search(r"(?i)\b(mock|test|fixture)\b", source):
                    continue

                written = set(getattr(function, "state_variables_written", []) or [])
                if not written.intersection(reward_vars):
                    continue
                if not written.intersection(balance_vars):
                    continue

                balance_match = _BALANCE_MUTATION_RE.search(source)
                reward_match = _REWARD_CHECKPOINT_RE.search(source)
                if balance_match is None or reward_match is None:
                    continue
                if reward_match.start() <= balance_match.start():
                    continue
                if _SAFE_ORDER_RE.search(source):
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " mutates balance or supply storage before reward checkpoint "
                    "state is written later in the same function. Candidate "
                    "reward skew: post-mutation checkpoint order.\n",
                ]
                results.append(self.generate_result(info))

        return results

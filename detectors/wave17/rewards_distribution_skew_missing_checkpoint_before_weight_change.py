"""
rewards-distribution-skew-missing-checkpoint-before-weight-change

Flags reward-bearing stake, pool membership, or reward weight mutations that
occur before the function checkpoints rewards or updates the reward accumulator.
This is source-order focused and intentionally narrower than the generic
missing updateReward detector.
"""

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _predicate_engine import _source_without_comments_and_strings
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RewardsDistributionSkewMissingCheckpointBeforeWeightChange(AbstractDetector):
    ARGUMENT = "rewards-distribution-skew-missing-checkpoint-before-weight-change"
    HELP = (
        "Reward-bearing stake, pool membership, or weight changes are applied "
        "before reward checkpointing or accumulator update."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor"
    WIKI_TITLE = "Reward weight or stake mutation before checkpoint"
    WIKI_DESCRIPTION = (
        "Reward accounting that uses a global accumulator must settle the "
        "current reward interval before changing stake, pool membership, or "
        "reward weights. Mutating the denominator or membership first makes the "
        "next checkpoint account for past rewards using post-mutation state."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A pool accrues rewards while pool A has weight 100. Before the "
        "accumulator is checkpointed, a caller changes pool A to weight 1 or "
        "adds a new listed pool. The next reward checkpoint applies the prior "
        "interval against the changed weights, skewing accrued rewards."
    )
    WIKI_RECOMMENDATION = (
        "Call updateReward, checkpointRewards, accrueRewards, updatePool, or "
        "an equivalent accumulator update before any stake, pool membership, "
        "or reward weight mutation."
    )

    _REWARD_CONTEXT_RE = re.compile(
        r"\b(reward\w*|emission\w*|incentive\w*|accReward\w*|"
        r"rewardPer\w*|rewardIndex\w*|checkpoint\w*|claimable\w*|"
        r"pendingReward\w*)",
        re.IGNORECASE,
    )
    _CHECKPOINT_RE = re.compile(
        r"\b(_?updateRewards?|_?updateReward|_?checkpointRewards?|"
        r"_?checkpointReward|_?checkpointPool|_?checkpointAccount|"
        r"_?checkpointUser|_?settleRewards?|_?settleReward|"
        r"_?accrueRewards?|_?accrueReward|_?updatePool|_?syncRewards?)\s*\(",
        re.IGNORECASE,
    )
    _ACCUMULATOR_UPDATE_RE = re.compile(
        r"\b(accRewardPerShare|accRewardPerWeight|rewardPerShare|"
        r"rewardPerToken|rewardPerWeight|rewardIndex|globalRewardIndex|"
        r"rewardAccumulator)\b\s*(?:\[[^\]]+\]|\.\w+)?\s*(?:\+=|=)",
        re.IGNORECASE,
    )
    _MUTATION_RE = re.compile(
        r"\b("
        r"balanceOf|balances|staked|stakeOf|stakes|stakedBalance|shares|"
        r"userShares|memberShares|poolShares|totalStaked|totalStake|"
        r"totalShares|totalWeight|poolWeight|poolWeights|rewardWeight|"
        r"rewardWeights|weights|allocPoint|allocationPoint|membership|"
        r"members|isMember|isPool|registeredPools|listedPools|rewardPools|"
        r"poolIds|poolCount"
        r")\b\s*(?:\[[^\]]+\]|\.\w+)?\s*(?:\+=|-=|=|\+\+|--)|"
        r"\b(pools|poolIds|rewardPools|listedPools|members)\s*\.\s*"
        r"(push|add|remove)\s*\(|"
        r"\b(_?addPool|_?removePool|_?joinPool|_?leavePool|"
        r"_?setPoolWeight|_?setRewardWeight|_?setWeight|"
        r"_?setAllocPoint|_?stake|_?unstake)\s*\(",
        re.IGNORECASE | re.DOTALL,
    )
    _SKIP_SOURCE_RE = re.compile(r"\b(mock|test|fixture)\b", re.IGNORECASE)

    _INCLUDE_LEAF_HELPERS = False
    _INVERSE_CEI = False

    @staticmethod
    def _source(obj) -> str:
        try:
            return obj.source_mapping.content or ""
        except Exception:
            return ""

    @staticmethod
    def _body_only(source: str) -> str:
        start = source.find("{")
        end = source.rfind("}")
        if start == -1:
            return source
        if end == -1 or end <= start:
            return source[start + 1 :]
        return source[start + 1 : end]

    @classmethod
    def _first_index(cls, regex: re.Pattern[str], source: str) -> int | None:
        match = regex.search(source)
        if match is None:
            return None
        return match.start()

    @classmethod
    def _first_checkpoint_index(cls, source: str) -> int | None:
        call_index = cls._first_index(cls._CHECKPOINT_RE, source)
        accumulator_index = cls._first_index(cls._ACCUMULATOR_UPDATE_RE, source)
        candidates = [idx for idx in (call_index, accumulator_index) if idx is not None]
        return min(candidates) if candidates else None

    @staticmethod
    def _function_kind(function) -> str:
        return str(getattr(function, "visibility", "") or "").lower()

    @classmethod
    def _has_checkpoint_modifier(cls, function) -> bool:
        try:
            modifiers = getattr(function, "modifiers", []) or []
        except Exception:
            modifiers = []
        for modifier in modifiers:
            name = getattr(modifier, "name", "") or str(modifier)
            if cls._CHECKPOINT_RE.search(f"{name}("):
                return True
        return False

    @classmethod
    def _contract_has_reward_context(cls, contract) -> bool:
        parts = [cls._source(contract)]
        try:
            parts.extend(cls._source(function) for function in contract.functions_and_modifiers_declared)
        except Exception:
            pass
        return bool(cls._REWARD_CONTEXT_RE.search("\n".join(parts)))

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if not self._contract_has_reward_context(contract):
                continue
            for function in contract.functions_and_modifiers_declared:
                if is_leaf_helper(function):
                    continue
                if self._function_kind(function) not in {"external", "public"}:
                    continue
                raw_source = self._source(function)
                if self._SKIP_SOURCE_RE.search(raw_source):
                    continue
                source = _source_without_comments_and_strings(self._body_only(raw_source))
                mutation_index = self._first_index(self._MUTATION_RE, source)
                if mutation_index is None:
                    continue
                if self._has_checkpoint_modifier(function):
                    continue
                checkpoint_index = self._first_checkpoint_index(source)
                if checkpoint_index is not None and checkpoint_index < mutation_index:
                    continue
                info = [
                    function,
                    " - rewards-distribution-skew-missing-checkpoint-before-weight-change: "
                    "weight, stake, or pool membership mutates before reward checkpointing.",
                ]
                results.append(self.generate_result(info))
        return results

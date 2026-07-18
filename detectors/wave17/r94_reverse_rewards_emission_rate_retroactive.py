"""
r94-reverse-rewards-emission-rate-retroactive — owned fixture-smoke/source-shape implementation.
Source: reverse-port-from-rust_wave1
"""

import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _predicate_engine import eval_function_match, eval_preconditions
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94ReverseRewardsEmissionRateRetroactive(AbstractDetector):
    ARGUMENT = "r94-reverse-rewards-emission-rate-retroactive"
    HELP = (
        "NOT_SUBMIT_READY detector-fixture-smoke-only: admin reward/emission "
        "rate setters write the new rate without first checkpointing accrual "
        "at the old rate."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "r94-reverse-rewards-emission-rate-retroactive.yaml"
    )
    WIKI_TITLE = "Reward rate setter retroactively rewrites the accrual window"
    WIKI_DESCRIPTION = (
        "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. This row "
        "proves only the owned Solidity shape where an admin-facing reward "
        "or emission setter writes `rewardRate` / `emissionRate` before any "
        "visible pool-wide checkpoint helper runs, so elapsed time since the "
        "last checkpoint is later accrued at the new rate."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A staking pool accrues rewards through an index updated from "
        "`rewardRate * (block.timestamp - lastUpdateTime)`. The admin lowers "
        "`rewardRate` from 100 to 10, but `setRewardRate()` writes the new "
        "rate first and omits `_updateRewardIndex()`. The next user action "
        "settles the entire elapsed window at 10 instead of 100, erasing "
        "most of the prior hour's accrual."
    )
    WIKI_RECOMMENDATION = (
        "Run the pool-wide checkpoint helper before every reward/emission rate "
        "mutation, then write the new rate and update timestamps or events. "
        "Keep this row NOT_SUBMIT_READY until evidence expands beyond the "
        "owned fixture pair."
    )

    SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
    COVERAGE_CLAIM = "detector_fixture_smoke_only"
    PROMOTION_ALLOWED = False

    _PRECONDITIONS = [
        {
            "contract.source_matches_regex": (
                "(emissionRate|rewardRate|rewardPerSecond|rewardsPerSecond|"
                "emissionsPerSecond|_rewardRate)"
            )
        }
    ]
    _MATCH = [
        {"function.kind": "external_or_public"},
        {
            "function.name_matches": (
                "(?i)^(setEmissionRate|setEmissionsPerSecond|setRewardRate|"
                "setRewardPerSecond|updateEmission|updateRewardRate|"
                "configureAssets|setAssetReward|updateAssetReward|"
                "setDistributionRate|notifyRewardAmount)$"
            )
        },
        {
            "function.body_contains_regex": (
                "(emissionRate\\s*=|rewardRate\\s*=|rewardPerSecond\\s*=|"
                "emissionsPerSecond\\s*=|_rewardRate\\s*=|"
                "assets\\[[^\\]]*\\]\\.emissionPerSecond\\s*=|"
                "asset\\.emissionPerSecond\\s*=)"
            )
        },
        {
            "function.body_not_contains_regex": (
                "(_updateRewardIndex|_updateAssetStateInternal|_updateAsset|"
                "_checkpoint|_accrueRewards|updateRewardsIndex|"
                "_updateDistributionState|updateAsset|"
                "_updateUserRewardsInternal|_updateState|accrue\\()"
            )
        },
        {"function.not_in_skip_list": True},
        {"function.not_leaf_helper": True},
        {"function.not_source_matches_regex": "(?i)\\b(mock|test|fixture)"},
    ]

    _INCLUDE_LEAF_HELPERS = False
    _INVERSE_CEI = False

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if not eval_preconditions(contract, self._PRECONDITIONS):
                continue

            for function in contract.functions_and_modifiers_declared:
                if not self._INCLUDE_LEAF_HELPERS and is_leaf_helper(function):
                    continue
                if not eval_function_match(function, self._MATCH):
                    continue
                info = [
                    function,
                    (
                        " — r94-reverse-rewards-emission-rate-retroactive: "
                        "reward/emission rate write occurs without a visible "
                        "checkpoint helper. See WIKI for details.\n"
                    ),
                ]
                results.append(self.generate_result(info))
        return results

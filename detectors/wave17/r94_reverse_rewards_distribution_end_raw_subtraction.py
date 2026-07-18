"""
r94-reverse-rewards-distribution-end-raw-subtraction — generated from reference/patterns.dsl/r94-reverse-rewards-distribution-end-raw-subtraction.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-reverse-rewards-distribution-end-raw-subtraction.yaml
Source: reverse-port-from-rust_wave1
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94ReverseRewardsDistributionEndRawSubtraction(AbstractDetector):
    ARGUMENT = "r94-reverse-rewards-distribution-end-raw-subtraction"
    HELP = "NOT_SUBMIT_READY detector-fixture-smoke-only: reward math uses raw `-` on distributionEnd / finishAt vs block.timestamp without a Math.min / lastTimeRewardApplicable clamp; underflows into uint-max once period ends or in unchecked{} block."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-reverse-rewards-distribution-end-raw-subtraction.yaml"
    WIKI_TITLE = "distributionEnd - block.timestamp without underflow clamp"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. Every Synthetix-style rewards contract has a `periodFinish` / `distributionEnd` timestamp. `earned()` and `rewardPerToken()` must compute elapsed time as `min(block.timestamp, periodFinish) - lastUpdate`, NOT `periodFinish - lastUpdate`. Once `block.timestamp > periodFinish`, the raw `periodFinish - block.timestamp` subtraction either reverts (Solidity >=0.8) — freezing claim / stake / withdraw — "
    WIKI_EXPLOIT_SCENARIO = "Classic Synthetix StakingRewards adds a new `emissionPerSecond` path and computes elapsed time as `elapsed = distributionEnd - lastUpdate;` inside an `unchecked { }` block (to save gas on the common case). After `distributionEnd` passes, a user calls `claim()` which triggers `_updateReward`. `lastUpdate` is still in the past, but `distributionEnd` is now also in the past and strictly less than `la"
    WIKI_RECOMMENDATION = "Use the canonical `lastTimeRewardApplicable() = Math.min(block.timestamp, periodFinish)` helper everywhere the elapsed window is computed. Never embed `periodFinish - X` inside an `unchecked { }` block. Add an invariant: `earned(u) <= totalRewardSupply()` at every entry point. Keep this row NOT_SUBMIT_READY until evidence expands beyond the owned fixture-smoke pair."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(distributionEnd|finishAt|endTime|periodFinish|rewardDuration|rewardsDuration|emissionEnd)'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': '(?i)^(_updateReward|updateRewards|_updateRewardIndex|earned|rewardPerToken|notifyRewardAmount|getRewardForDuration|claimable|accruedRewards|_accrueRewards|rewardRate)$'}, {'function.body_contains_regex': '(distributionEnd|finishAt|endTime|periodFinish|emissionEnd|rewardsDuration)\\s*-\\s*\\w+|\\w+\\s*-\\s*(distributionEnd|finishAt|endTime|periodFinish|emissionEnd)'}, {'function.body_not_contains_regex': '(Math\\.min|math\\.min|MathUpgradeable\\.min|_min\\s*\\(|block\\.timestamp\\s*<\\s*(distributionEnd|finishAt|endTime|periodFinish)|periodFinish\\s*<\\s*block\\.timestamp|lastTimeRewardApplicable|trySub)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = False
    _INVERSE_CEI = False

    def _detect(self):
        results = []
        for c in self.contracts:
            if is_vendored_or_test_contract(c):
                continue
            if not eval_preconditions(c, self._PRECONDITIONS):
                continue
            for f in c.functions_and_modifiers_declared:
                if not self._INCLUDE_LEAF_HELPERS and is_leaf_helper(f):
                    continue
                if not eval_function_match(f, self._MATCH):
                    continue
                info = [f, f" — r94-reverse-rewards-distribution-end-raw-subtraction: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results

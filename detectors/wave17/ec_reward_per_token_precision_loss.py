"""
ec-reward-per-token-precision-loss — generated from reference/patterns.dsl/ec-reward-per-token-precision-loss.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py ec-reward-per-token-precision-loss.yaml
Source: economic-mining-R61
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EcRewardPerTokenPrecisionLoss(AbstractDetector):
    ARGUMENT = "ec-reward-per-token-precision-loss"
    HELP = "rewardPerToken accumulator computed as reward/totalStaked without 1e12+ precision scaling; small rewards silently truncate to zero and are permanently lost."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/ec-reward-per-token-precision-loss.yaml"
    WIKI_TITLE = "Staking reward precision loss — rewardPerToken not scaled before division"
    WIKI_DESCRIPTION = "The reward distribution function computes an accumulated rewardPerToken by dividing a reward increment by totalStaked without first multiplying by a precision factor (1e18 or 1e12). For large totalStaked values and small periodic reward additions, the division result is zero every period, permanently dropping all rewards. The corresponding claim function multiplies by the same (missing) scaling fa"
    WIKI_EXPLOIT_SCENARIO = "totalStaked = 1e24 (1M tokens with 18 decimals). Daily reward = 1000e18 tokens. rewardPerToken += 1000e18 / 1e24 = 0 (truncates). Over 365 days: 365,000 tokens in rewards silently disappear. With 1e18 scaling: rewardPerToken += 1000e18 * 1e18 / 1e24 = 1e15 (valid)."
    WIKI_RECOMMENDATION = "Always scale before dividing: `rewardPerToken += reward * 1e18 / totalStaked`. When claiming, divide back out: `earned = userStake * rewardPerTokenAccumulated / 1e18`. Use a named constant ACC_PRECISION = 1e18 or 1e12 consistently across all reward math."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'rewardPerToken|accRewardPerShare|rewardPerShare|pendingReward'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': 'rewardPerToken|accRewardPerShare|rewardPerShare'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.body_contains_regex': 'reward.*\\/.*totalStaked|reward.*\\/.*totalSupply|rewardDelta.*\\/.*supply'}, {'function.body_not_contains_regex': '\\*\\s*1e18|\\*\\s*1e12|\\*\\s*PRECISION|\\*\\s*1_000_000|\\*\\s*ACC_PRECISION|\\*.*1000000'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — ec-reward-per-token-precision-loss: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results

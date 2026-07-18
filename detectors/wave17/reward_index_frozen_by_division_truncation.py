"""
reward-index-frozen-by-division-truncation — generated from reference/patterns.dsl/reward-index-frozen-by-division-truncation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py reward-index-frozen-by-division-truncation.yaml
Source: auditooor-R75-c4-yield-2024-10-loopfi-25
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RewardIndexFrozenByDivisionTruncation(AbstractDetector):
    ARGUMENT = "reward-index-frozen-by-division-truncation"
    HELP = "NOT_SUBMIT_READY fixture-smoke/source-shape proof only: reward updater does `lastBalance += accrued` even when `accrued / totalShares == 0`; rewards silently burn when totalShares is large or decimals small."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/reward-index-frozen-by-division-truncation.yaml"
    WIKI_TITLE = "Reward index rounds to zero but lastBalance still advances, permanently stranding rewards"
    WIKI_DESCRIPTION = "A classic MasterChef-style reward distributor computes `deltaIndex = accrued / totalShares` and updates both the index and a `lastBalance` watermark. If `accrued * PRECISION < totalShares`, deltaIndex truncates to 0 — the index does not advance, no user can claim these rewards in the future. But the code unconditionally sets `lastBalance += accrued`, consuming the reward balance so the next update"
    WIKI_EXPLOIT_SCENARIO = "LoopFi RewardManager on USDC: totalShares = 200M * 1e18, accrued = 100 USDC = 100e6. deltaIndex = 100e6 / 200e24 = 0. Index unchanged; lastBalance += 100e6. Reward token is now in the contract but unmatchable to any user. Repeated every block by frequent getRewards() calls → perpetual drain."
    WIKI_RECOMMENDATION = "Pair the writes: `uint256 delta = accrued / totalShares; if (delta == 0) return; index += delta; lastBalance += delta * totalShares;`. This guarantees lastBalance only advances by the amount actually credited to the index, and remainders accumulate until they cross the threshold."

    _PRECONDITIONS = [{'contract.has_state_var_matching': '(?i)(lastBalance|lastRewardBalance|lastReward|rewardIndex|accRewardPerShare)'}, {'contract.has_function_matching': '(?i)(_updateRewardIndex|_updateIndex|updateRewards|_accrueRewards)'}]
    _MATCH = [{'function.kind': 'internal_or_private'}, {'function.name_matches': '(?i)(_updateRewardIndex|_updateIndex|updateRewards|_accrueRewards)'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.body_contains_regex': '(?i)(divDown|/\\s*totalShares|/\\s*totalSupply)'}, {'function.writes_storage_matching': '(?i)(lastBalance|lastRewardBalance|lastReward)'}, {'function.writes_storage_matching': '(?i)(index|rewardIndex|accRewardPerShare)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.body_not_contains_regex': '(?i)(delta(Index|RewardIndex)?\\s*\\*\\s*total(Shares|Supply)|delta(Index|RewardIndex)?\\s*\\.mulDown\\s*\\(\\s*total(Shares|Supply)|ceilDiv|mulDivUp|if\\s*\\(\\s*delta(Index|RewardIndex)?\\s*==\\s*0\\s*\\)\\s*return)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — reward-index-frozen-by-division-truncation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results

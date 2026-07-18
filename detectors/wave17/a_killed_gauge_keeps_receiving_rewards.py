"""
a-killed-gauge-keeps-receiving-rewards — generated from reference/patterns.dsl/a-killed-gauge-keeps-receiving-rewards.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-killed-gauge-keeps-receiving-rewards.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AKilledGaugeKeepsReceivingRewards(AbstractDetector):
    ARGUMENT = "a-killed-gauge-keeps-receiving-rewards"
    HELP = "Reward distribution keeps crediting a killed gauge because the post-kill allocation path writes fresh claimable rewards without checking that the gauge is still alive."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-killed-gauge-keeps-receiving-rewards.yaml"
    WIKI_TITLE = "Killed gauge still accrues fresh emissions after kill"
    WIKI_DESCRIPTION = "When `killGauge()` or an equivalent admin shutdown path marks a gauge dead, later reward-allocation code must stop crediting that gauge. A common failure mode is: the kill path transfers or clears the old claimable balance, but `distributeRewards` / `notifyRewardAmount` / `updateReward` still writes new entries into `claimableRewardsByGauge[gauge]` because it never checks `isKilled[gauge]` or `isA"
    WIKI_EXPLOIT_SCENARIO = "Governance kills gauge `G` after deprecating its pool. The kill path clears `claimableRewardsByGauge[G]` and flips `isKilled[G] = true`. In the next epoch, `distributeRewards(G, amount)` still executes `claimableRewardsByGauge[G] += amount` because the function lacks any alive-check. Fresh emissions keep accumulating on a gauge that should no longer participate, distorting global reward distributi"
    WIKI_RECOMMENDATION = "Gate every reward-allocation path on the gauge's liveness state before writing claimable rewards. Typical fixes are `require(!isKilled[gauge])`, `if (!isAlive[gauge]) return;`, or routing killed-gauge emissions to a recovery / redistribution path instead of mutating per-gauge reward state."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'claimableRewards|rewardsByGauge|pendingRewardsByGauge'}, {'contract.has_state_var_matching': 'isKilled|killedGauges|isAlive|aliveGauges'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'distribute|notifyReward|queueReward|allocateReward|accrueReward|updateReward'}, {'function.writes_storage_matching': 'claimableRewards|rewardsByGauge|pendingRewardsByGauge'}, {'function.body_contains_regex': 'gauge'}, {'function.body_not_contains_regex': 'isKilled|killedGauges|isAlive|aliveGauges|onlyLiveGauge|liveGaugeOnly'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — a-killed-gauge-keeps-receiving-rewards: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results

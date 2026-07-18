"""
gauge-kill-before-first-period-rewards-lost — generated from reference/patterns.dsl/gauge-kill-before-first-period-rewards-lost.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py gauge-kill-before-first-period-rewards-lost.yaml
Source: solodit/gauge-kill-rewards
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GaugeKillBeforeFirstPeriodRewardsLost(AbstractDetector):
    ARGUMENT = "gauge-kill-before-first-period-rewards-lost"
    HELP = "`killGauge()` flips the gauge's `isAlive` flag without first flushing any pending-reward balance to LPs or to a treasury. If the gauge is killed mid-epoch (or before the first period finishes), rewards that were already accrued but not yet distributed are stranded in the gauge contract with no claim"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/gauge-kill-before-first-period-rewards-lost.yaml"
    WIKI_TITLE = "Gauge kill path does not flush pending rewards: stranded-reward DoS"
    WIKI_DESCRIPTION = "Velodrome-style voting-reward / gauge contracts expose a `killGauge`/`deactivate` admin hook that marks a gauge dead so it stops receiving new emissions. A correct implementation sweeps the remaining reward balance back to the voter or to a recovery address before flipping the flag; a buggy implementation simply sets `isAlive = false`. Because most gauges gate `claimRewards` on `isAlive == true`, "
    WIKI_EXPLOIT_SCENARIO = "Admin kills a gauge at week 3 of what was supposed to be a 4-week incentive campaign. The gauge still holds `X` tokens of undistributed rewards. `killGauge()` sets `isAlive = false`. LPs call `claimRewards` and hit the `require(isAlive)` guard — permanent revert. The `X` tokens are now uncollectable without a protocol upgrade. In the Aerodrome / Velodrome / Thena families this is a recurring audit"
    WIKI_RECOMMENDATION = "In `killGauge`, first call `distributeRewards()` / `notifyRewardAmount()` / `claimForAll()` to flush the remaining balance into the voter-reward pool. Only then flip `isAlive = false`. As belt-and-suspenders, expose a `rescueRewards(address to)` hook that works ONLY on killed gauges so a treasury ca"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'gauge|votingReward|rewardPool|killed|isAlive'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(killGauge|_killGauge|kill|deactivate|deactivateGauge|disableGauge|setKilled)$'}, {'function.writes_storage_matching': 'killed|isAlive|alive|deactivated|active'}, {'function.body_not_contains_regex': 'claimReward|notifyReward|_distribute|sweepRewards|flushReward|safeTransfer\\s*\\([^)]*reward|transfer\\s*\\([^)]*reward'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — gauge-kill-before-first-period-rewards-lost: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results

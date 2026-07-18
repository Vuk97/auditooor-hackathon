"""
gauge-deactivate-loses-pending-rewards — generated from reference/patterns.dsl/gauge-deactivate-loses-pending-rewards.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py gauge-deactivate-loses-pending-rewards.yaml
Source: solodit-C0198
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GaugeDeactivateLosesPendingRewards(AbstractDetector):
    ARGUMENT = "gauge-deactivate-loses-pending-rewards"
    HELP = "Admin killGauge/deactivateGauge path deletes gauge state without snapshotting pending per-user rewards first. All users with unclaimed accruals in the current epoch lose those rewards permanently."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/gauge-deactivate-loses-pending-rewards.yaml"
    WIKI_TITLE = "Gauge deactivation loses pending user rewards — no snapshot before state delete"
    WIKI_DESCRIPTION = "Gauge-style reward contracts (Curve/Velodrome/Solidly fork lineage) derive per-user rewards from live gauge state: totalSupply, rewardPerToken, periodFinish. When an admin calls killGauge / deactivateGauge / removeGauge and the function deletes or zeroes that state without first flushing each user's accrued reward into a per-user claimable ledger, every unclaimed accrual earned during the current "
    WIKI_EXPLOIT_SCENARIO = "Users deposit LP into a gauge and accrue rewards across an epoch. Two days before periodFinish the admin calls killGauge(lpToken) to disable a deprecated pool. The kill path sets `isAlive[gauge] = false` and deletes `rewardPerTokenStored[gauge]`. A user who has earned but not yet claimed rewards calls claim(): the derivation `earned(user) = balanceOf(user) * (rewardPerToken - userRewardPerTokenPai"
    WIKI_RECOMMENDATION = "Before modifying gauge state in the deactivation path, iterate (or lazy-snapshot via a checkpoint) and move each user's accrued reward into a per-user claimable ledger that survives the kill. Common idioms: call an internal `_flushRewards(gauge)` that updates rewardPerTokenStored and writes `pending"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'gauge|gauges|gaugeInfo|votingReward'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'killGauge|deactivateGauge|removeGauge|_killGauge|retireGauge|pauseGauge'}, {'function.has_modifier': {'includes': ['onlyOwner', 'onlyAdmin', 'onlyGovernance', 'onlyEmergencyAdmin'], 'negate': False}}, {'function.writes_storage_matching': 'gauge|gauges|gaugeState|active'}, {'function.body_not_contains_regex': 'snapshotRewards|_flushRewards|accrueBeforeKill|_migratePending|pendingRewards|claimPending|finalizeRewards'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — gauge-deactivate-loses-pending-rewards: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results

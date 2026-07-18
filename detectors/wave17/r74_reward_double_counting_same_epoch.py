"""
r74-reward-double-counting-same-epoch — generated from reference/patterns.dsl/r74-reward-double-counting-same-epoch.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r74-reward-double-counting-same-epoch.yaml
Source: r74b-cross-firm-cs+tob
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R74RewardDoubleCountingSameEpoch(AbstractDetector):
    ARGUMENT = "r74-reward-double-counting-same-epoch"
    HELP = "Epoch-indexed reward claim transfers before marking (user, epoch) as claimed; a second call in the same epoch (or after a reward-state reroll) can double-count."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r74-reward-double-counting-same-epoch.yaml"
    WIKI_TITLE = "Epoch-indexed reward claim missing per-epoch claimed-mark before transfer"
    WIKI_DESCRIPTION = "The claim function reads rewards[user][epoch], transfers that amount, and optionally advances lastUpdate at the end — but does not mark the specific (user, epoch) pair as consumed. When the epoch boundary rolls while a multisig / batch is in flight, or a governance proposal reroll changes the per-epoch accounting, the same epoch's accrual can be transferred twice."
    WIKI_EXPLOIT_SCENARIO = "A gauge uses weekly epochs. The user calls claim() at week 10 and receives rewards[user][9]. Immediately after, governance executes a reroll that re-aggregates week 9 rewards across all gauges (backfilling an oracle correction). The reroll writes a new value into rewards[user][9]. The user calls claim() again, reads the new (larger) rewards[user][9], and is paid for week 9 twice — because the firs"
    WIKI_RECOMMENDATION = "Before calling transfer, atomically mark the claim: `require(!claimed[user][epoch], 'already claimed'); claimed[user][epoch] = true;` OR `delete rewards[user][epoch];`. Follow the checks-effects-interactions order even when a reentrancy modifier is in place, because the second-claim vector is not re"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(epoch|period|cycle|weeklyReward|dailyReward)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(claim|claimRewards|distribute|harvest|collectRewards|claimFor|claimAll)'}, {'function.body_contains_regex': '(epoch|period|cycle|week)\\s*\\[|rewards?\\s*\\[\\s*\\w+\\s*\\]\\s*\\[\\s*(epoch|period|cycle|week)|epochReward|periodReward'}, {'function.body_not_contains_regex': 'claimed\\s*\\[[^\\]]+\\]\\s*\\[[^\\]]+\\]\\s*=\\s*true|lastClaimedEpoch|lastClaimed\\s*\\[|delete\\s+\\w*rewards?\\s*\\[|rewards?\\s*\\[[^\\]]+\\]\\s*\\[[^\\]]+\\]\\s*=\\s*0|lastUpdate'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — r74-reward-double-counting-same-epoch: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results

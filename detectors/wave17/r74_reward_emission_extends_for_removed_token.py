"""
r74-reward-emission-extends-for-removed-token — generated from reference/patterns.dsl/r74-reward-emission-extends-for-removed-token.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r74-reward-emission-extends-for-removed-token.yaml
Source: r74b-cross-firm-tob+cs+oz
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R74RewardEmissionExtendsForRemovedToken(AbstractDetector):
    ARGUMENT = "r74-reward-emission-extends-for-removed-token"
    HELP = "Reward-notify path extends a reward schedule without first verifying the reward token is still active; emission can continue after governance removal, stranding or double-paying."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r74-reward-emission-extends-for-removed-token.yaml"
    WIKI_TITLE = "Reward schedule extended for removed / inactive reward token"
    WIKI_DESCRIPTION = "The staking contract supports adding and removing reward tokens dynamically. The removal path wipes claim-side accounting but does not zero the emission schedule, and the notify/extend path does not check the token is currently active. Once governance removes a token, subsequent notifyRewardAmount calls (permissioned or permissionless depending on design) re-inflate the schedule, continuing to emi"
    WIKI_EXPLOIT_SCENARIO = "A gauge supports three reward tokens. Governance removes token B after a partnership ends. An attacker calls notifyRewardAmount(B, large) using dust they sent in. periodFinish for B is extended one week. Because removal only cleared user-side claim state, the rewardRate for B is re-armed; the contract now pays out rewards for B to stakers who entered AFTER the removal — but the B balance in the co"
    WIKI_RECOMMENDATION = "In every notify/extend entry point, require that the reward token is currently on the active-tokens list: `require(isRewardToken[token], 'inactive reward token');`. Complement with a removal function that sets rewardRate[token] = 0 and periodFinish[token] = block.timestamp atomically, and blocks fur"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(reward|gauge|bribe|emission|incentive)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(notifyRewardAmount|_notify|addReward|extendRewards|fundReward)'}, {'function.writes_storage_matching': 'reward|rewardRate|rewardsDuration|periodFinish|emission'}, {'function.body_not_contains_regex': 'isRewardToken|rewardActive|rewardTokens\\[[^\\]]+\\]\\.active|require\\s*\\([^)]*active|!removed|isActive\\s*\\['}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — r74-reward-emission-extends-for-removed-token: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results

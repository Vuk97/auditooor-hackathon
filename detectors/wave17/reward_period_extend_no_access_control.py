"""
reward-period-extend-no-access-control — generated from reference/patterns.dsl/reward-period-extend-no-access-control.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py reward-period-extend-no-access-control.yaml
Source: solodit/sherlock/zivoe-H1-31886
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RewardPeriodExtendNoAccessControl(AbstractDetector):
    ARGUMENT = "reward-period-extend-no-access-control"
    HELP = "Permissionless reward-notification entry point (notifyReward/depositReward) lacks role gate and accepts zero reward, allowing anyone to repeatedly roll periodFinish forward and dilute the per-second emission rate to stakers."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/reward-period-extend-no-access-control.yaml"
    WIKI_TITLE = "Permissionless reward distributor: zero-deposit extends periodFinish, dilutes emission"
    WIKI_DESCRIPTION = "A Synthetix-style staking rewards contract exposes `depositReward(token, amount)` or `notifyRewardAmount(amount)` as `external` without any role modifier. The function rewrites `periodFinish = block.timestamp + rewardsDuration` whenever called, even when `amount == 0`. A griefer calls it mid-period: no tokens move, but the finish timestamp slides forward, the rewardRate is recomputed as `(0 + left"
    WIKI_EXPLOIT_SCENARIO = "Protocol schedules 10 DAI of rewards over 10 days. On day 5, attacker calls `depositReward(DAI, 0)`. The function enters the `block.timestamp < periodFinish` branch: leftover = 5 * rewardRate, new rewardRate = leftover / 10 days = rewardRate / 2, new periodFinish = now + 10 days. Honest stakers who withdraw on day 10 collect only ~7.5 DAI instead of 10. Attacker repeats each day; rewards are stret"
    WIKI_RECOMMENDATION = "Gate `notifyReward` / `depositReward` behind a whitelisted distributor role. Additionally revert on `amount == 0` to remove even the accidental dilution vector. If the entry must stay permissionless (e.g., an airdrop puller), separate the time-write: only advance `periodFinish` when `amount > 0`."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(periodFinish|rewardsDuration|rewardRate)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(notifyReward|notifyRewardAmount|depositReward|depositRewards|addReward|addRewards|setReward|setRewards|fundReward|fundRewards|extendRewardPeriod)$'}, {'function.body_contains_regex': 'periodFinish\\s*=|lastUpdateTime\\s*=|rewardRate\\s*='}, {'function.has_modifier': {'includes': ['onlyOwner', 'onlyRole', 'onlyAdmin', 'onlyDistributor', 'onlyGov', 'onlyKeeper', 'onlyRewardManager', 'onlyEmissionAdmin', 'requiresDistributorRole'], 'negate': True}}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*(?:msg\\.sender\\s*==\\s*(owner|admin|distributor)|_?[A-Za-z]\\w*\\s*\\(\\s*msg\\.sender\\s*\\)|hasRole\\s*\\(\\s*[A-Z_][A-Z0-9_]*\\s*,\\s*msg\\.sender\\s*\\))'}, {'function.body_not_contains_regex': '(reward|amount)\\s*==\\s*0|(reward|amount)\\s*>\\s*0|require\\s*\\(\\s*(reward|amount)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — reward-period-extend-no-access-control: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results

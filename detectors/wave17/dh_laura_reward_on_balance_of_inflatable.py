"""
dh-laura-reward-on-balance-of-inflatable — generated from reference/patterns.dsl/dh-laura-reward-on-balanceOf-inflatable.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py dh-laura-reward-on-balanceOf-inflatable.yaml
Source: defihacklabs/LAURAToken-2025-01+LPMine-2025-01
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DhLauraRewardOnBalanceOfInflatable(AbstractDetector):
    ARGUMENT = "dh-laura-reward-on-balance-of-inflatable"
    HELP = "Reward math uses live `balanceOf(pool)` instead of a tracked `totalStaked` — attacker inflates by direct transfer."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/dh-laura-reward-on-balanceOf-inflatable.yaml"
    WIKI_TITLE = "Reward accounting reads balanceOf(pool) — inflatable by direct transfer"
    WIKI_DESCRIPTION = "Deriving share-of-pool from `balanceOf(address(this))` lets anyone dilute or concentrate rewards with a single `transfer` into the contract. The staking invariant `user.amount * totalReward / totalStaked` must use a tracked deposits counter, not token balance."
    WIKI_EXPLOIT_SCENARIO = "LAURAToken 2025-01 / LPMine 2025-01: `pendingReward(user) = user.amount * accRewardPerShare * balanceOf(pool) / 1e18`. Attacker transferred pool-token directly (without staking), increased `balanceOf(pool)`, triggered harvest update, then withdrew reward amplified far beyond their stake proportion."
    WIKI_RECOMMENDATION = "Introduce `uint256 totalDeposited` updated only inside `deposit`/`withdraw`. Never use `token.balanceOf(address(this))` in reward math."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'reward|pendingReward|getReward|accReward'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.body_contains_regex': 'balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)\\s*\\)|\\.balanceOf\\s*\\(\\s*pool\\s*\\)'}, {'function.body_contains_regex': 'reward|harvest|claim|accRewardPerShare'}, {'function.body_not_contains_regex': 'totalStaked|totalDeposits|stakedAmount|_totalDeposited'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — dh-laura-reward-on-balance-of-inflatable: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results

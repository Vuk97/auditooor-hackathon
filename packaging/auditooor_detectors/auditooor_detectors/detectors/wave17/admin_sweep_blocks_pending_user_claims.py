"""
admin-sweep-blocks-pending-user-claims — generated from reference/patterns.dsl/admin-sweep-blocks-pending-user-claims.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py admin-sweep-blocks-pending-user-claims.yaml
Source: auditooor-round-32
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AdminSweepBlocksPendingUserClaims(AbstractDetector):
    ARGUMENT = "admin-sweep-blocks-pending-user-claims"
    HELP = "Admin sweep/rescue/emergencyWithdraw transfers the entire contract balance without subtracting pending unclaimed user rewards/escrow. Users with accrued-but-unclaimed balances lose the ability to claim."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/admin-sweep-blocks-pending-user-claims.yaml"
    WIKI_TITLE = "Admin sweep transfers full contract balance, stranding pending user claims"
    WIKI_DESCRIPTION = "The contract tracks per-user pending/unclaimed/accrued balances (rewards, escrow, vesting) but its admin sweep / rescue / emergencyWithdraw function transfers the entire token balance out without subtracting those outstanding obligations. After the sweep, the contract's balance is below the sum of what users have earned-but-not-yet-claimed, so every pending claim permanently reverts on insufficien"
    WIKI_EXPLOIT_SCENARIO = "A staking contract pays rewards via a pull model: users accrue `pendingReward[user]` and call `claim()` to receive it. The admin runs `sweep(rewardToken)` to recover what they believe is surplus. The sweep moves the full `rewardToken.balanceOf(address(this))` out, but `sum(pendingReward[*])` was $50k of that balance. Every subsequent user `claim()` reverts because the contract no longer holds enou"
    WIKI_RECOMMENDATION = "Before transferring out any contract balance from a sweep/rescue entry-point, subtract the outstanding pending/unclaimed/accrued total: `uint256 reserved = totalPending; uint256 sweepable = balance - reserved; require(sweepable >= amount);`. Maintain a running `totalPending` (or equivalent accumulat"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'pending|escrow|unclaimed|reward|accruedReward'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'sweep|_sweep|rescue|emergencyWithdraw|adminWithdraw|recoverTokens'}, {'function.has_modifier': {'includes': ['onlyOwner', 'onlyAdmin', 'onlyRoles', 'onlyGovernance'], 'negate': False}}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.body_contains_regex': 'balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)|this\\.balance|totalBalance|\\.transfer\\s*\\(.*balanceOf'}, {'function.body_not_contains_regex': 'unclaimed|pending|_accrued|reserveFor|require\\s*\\(.*balance\\s*>\\s*unclaimed|balance\\s*-\\s*pending'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — admin-sweep-blocks-pending-user-claims: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results

"""
referral-bonus-uses-cumulative-not-active — generated from reference/patterns.dsl/referral-bonus-uses-cumulative-not-active.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py referral-bonus-uses-cumulative-not-active.yaml
Source: DeFiHackLabs/Grizzifi (2025-08, $61K) — _incrementUplineTeamCount used totalInvested (cumulative, withdrawal-insensitive) instead of active-investment balance, letting an attacker deposit+withdraw across 30 sybil accounts and inflate upline referral bonuses
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ReferralBonusUsesCumulativeNotActive(AbstractDetector):
    ARGUMENT = "referral-bonus-uses-cumulative-not-active"
    HELP = "Referral / team-count / bonus path reads totalInvested (cumulative, monotonic) instead of the active balance. Sybil accounts that deposit+withdraw still count toward upline bonuses, inflating rewards."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/referral-bonus-uses-cumulative-not-active.yaml"
    WIKI_TITLE = "Referral bonuses credited from cumulative deposits (survives withdraw)"
    WIKI_DESCRIPTION = "A referral system increments upline counters, tier levels, or bonus pots based on totalInvested / cumulativeDeposits / lifetimeDeposits — counters that only ever grow and are not decreased on withdraw. An attacker builds a sybil referral chain where each node deposits the minimum required, triggers the bonus-credit path, then withdraws. The totalInvested counter survives the withdrawal, so each sy"
    WIKI_EXPLOIT_SCENARIO = "Grizzifi (2025-08, $61K). _incrementUplineTeamCount() checked totalInvested for each upline, not the current active-investment slot. Attacker created 30 sybil accounts chained as referrer->referred->referred->... Each account called harvestHoney(0, 10 ether, upline) to register the deposit and trigger upline credit, then withdrew via collectRefBonus. totalInvested for each sybil remained at 10e18,"
    WIKI_RECOMMENDATION = "Credit referral bonuses against active balance only: `if (activeInvestment[referee] >= tierMin) teamCount[upline] += 1`. Decrement teamCount / bonus eligibility when the referee withdraws below the tier threshold. Alternatively, checkpoint bonuses per epoch and require the referee's active balance t"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'referral|referrer|upline|team|sponsor'}, {'contract.has_state_var_matching': 'totalInvested|cumulativeDeposit|lifetimeDeposit|totalDeposited'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(harvestHoney|harvest|deposit|invest|stake|registerReferral|bindReferral|_incrementUplineTeamCount|distributeBonus|_creditReferralBonus|refer).*$'}, {'function.body_contains_regex': 'totalInvested|cumulativeDeposit|lifetimeDeposit|totalDeposited'}, {'function.body_not_contains_regex': 'activeInvestment|activeBalance|activeStake|currentStake|currentBalance|active\\[|isActive\\s*\\(|activePrincipal'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — referral-bonus-uses-cumulative-not-active: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results

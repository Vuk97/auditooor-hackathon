"""
validator-state-transition-stake-lock — generated from reference/patterns.dsl/validator-state-transition-stake-lock.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py validator-state-transition-stake-lock.yaml
Source: solodit/C0377
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ValidatorStateTransitionStakeLock(AbstractDetector):
    ARGUMENT = "validator-state-transition-stake-lock"
    HELP = "Stake/unstake/withdraw path reads validator lifecycle state (Active|Jailed|Slashed|Exited) but does not branch on every non-Active transition; stakes entering an unhandled state become locked, uncreditable, or stealable by subsequent depositors."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/validator-state-transition-stake-lock.yaml"
    WIKI_TITLE = "Validator state transition leaves stake locked or double-counted"
    WIKI_DESCRIPTION = "Staking contracts that track per-validator lifecycle (Active|Jailed|Slashed|Exited) must settle reward accruals and refund principal on EVERY transition. When stake/unstake/claim paths inspect the state field but only handle a subset of terminal states, stakes routed through the unhandled branch are silently dropped, double-awarded, or become unreachable. This is the C0377 bug shape observed acros"
    WIKI_EXPLOIT_SCENARIO = "A validator transitions Active -> Jailed between a user's deposit and a subsequent rewards sync. The contract's stake() path checks validatorState but only branches on Active vs Exited; the Jailed case falls through and the deposit is credited to the pre-Jailed reward bucket. The previous staker withdraws the combined balance before the current staker can claim, permanently locking or stealing the"
    WIKI_RECOMMENDATION = "Every user-facing stake lifecycle function (stake, unstake, withdraw, exit, claimStake) MUST branch on all non-Active validator states — Jailed, Slashed, and Exited — and either refund, quarantine, or reject the operation explicitly. Add a default revert for unknown states. Settle reward accruals be"

    _PRECONDITIONS = [{'contract.has_state_var_matching': 'validator|validators|stakeInfo|validatorState'}, {'contract.source_matches_regex': '(Active|Jailed|Slashed|Exited)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(stake|unstake|withdraw|_unstake|exit|claimStake)$'}, {'function.body_contains_regex': 'validatorState|\\.state\\b|\\.status\\b|ValidatorState|state\\s*==\\s*(Active|Jailed|Slashed|Exited)'}, {'function.body_not_contains_regex': 'Exited[\\s\\S]*Slashed[\\s\\S]*Jailed|Jailed[\\s\\S]*Slashed[\\s\\S]*Exited|Slashed[\\s\\S]*Exited[\\s\\S]*Jailed|Exited[\\s\\S]*Jailed[\\s\\S]*Slashed|Slashed[\\s\\S]*Jailed[\\s\\S]*Exited|Jailed[\\s\\S]*Exited[\\s\\S]*Slashed'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — validator-state-transition-stake-lock: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results

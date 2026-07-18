"""
reentrancy-token-drain — generated from reference/patterns.dsl/reentrancy-token-drain.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py reentrancy-token-drain.yaml
Source: solodit/C0117
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ReentrancyTokenDrain(AbstractDetector):
    ARGUMENT = "reentrancy-token-drain"
    HELP = "Withdraw/claim/unstake function performs external token transfer before deducting storage balance and lacks a reentrancy guard. Classic token-drain reentrancy."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/reentrancy-token-drain.yaml"
    WIKI_TITLE = "Reentrancy in withdraw-class function allows token drain"
    WIKI_DESCRIPTION = "A function whose name is in the withdraw/claim/unstake/redeem/exit/cashOut/collect family performs an external call (token transfer, ETH send, or arbitrary contract call) and only AFTER the call updates the user's balance or stake in storage. With no nonReentrant guard, the callee can reenter and re-invoke the withdraw path before the storage write completes, draining the contract of tokens."
    WIKI_EXPLOIT_SCENARIO = "Attacker deploys a contract that, upon receiving tokens or ETH, reenters the victim's withdraw function. Because the caller's storage balance is only decremented AFTER the external call, every reentrant invocation still sees the original balance and transfers again. The attack repeats until the contract is drained."
    WIKI_RECOMMENDATION = "Apply OpenZeppelin ReentrancyGuard (nonReentrant modifier) OR strictly reorder to Checks-Effects-Interactions: deduct the storage balance before performing the external transfer."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(withdraw|claim|unstake|redeem|exit|cashOut|collect)'}, {'function.has_external_call': True}, {'function.post_external_call_mutates_state': True}, {'function.has_modifier': {'includes': ['nonReentrant', 'reentrancyGuard', 'lock', 'noReentrancy', 'nonreentrant'], 'negate': True}}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — reentrancy-token-drain: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results

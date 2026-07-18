"""
subtraction-without-gt-check — generated from reference/patterns.dsl/subtraction-without-gt-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py subtraction-without-gt-check.yaml
Source: solodit-cluster-C0005
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SubtractionWithoutGtCheck(AbstractDetector):
    ARGUMENT = "subtraction-without-gt-check"
    HELP = "External/public function subtracts from a balance/shares/total state variable with no `require(x >= y)` pre-check — silent underflow on solc < 0.8, uninformative revert-DoS on >= 0.8."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/subtraction-without-gt-check.yaml"
    WIKI_TITLE = "Subtraction of state variable without >= check"
    WIKI_DESCRIPTION = "A public/external function writes to a state variable named balance/balances/shares/total and contains a bare `-=` or `-` subtraction of that variable without a dominating `require(state >= amount)` or `if (state < amount) revert …` guard. On Solidity < 0.8.0 the subtraction silently underflows to 2^256-1, letting a griefer drain subsequent users. On >= 0.8.0 the subtraction reverts with `Panic(0x"
    WIKI_EXPLOIT_SCENARIO = "A staker exposes `function unstake(uint256 amount) external { shares[msg.sender] -= amount; _payout(amount); }`. A user with 1e18 shares calls `unstake(2e18)`: on solc 0.7.x their share balance wraps to type(uint256).max and they drain every other staker's claim. On solc 0.8.x the tx reverts with `Panic(0x11)`, the frontend displays an opaque error, the user assumes the contract is paused, and ope"
    WIKI_RECOMMENDATION = "Add an explicit `require(state[msg.sender] >= amount, \"INSUFFICIENT_BALANCE\")` or custom-error `if (state[msg.sender] < amount) revert InsufficientBalance(state[msg.sender], amount);` at the top of every function that subtracts from a balance/shares/total mapping. Prefer a named custom error so th"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.writes_storage_matching': 'balance|balances|shares|total'}, {'function.body_contains_regex': 'balances?\\[\\s*\\w+\\s*\\]\\s*-=|shares\\[\\s*\\w+\\s*\\]\\s*-=|total\\w*\\s*-='}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*balance|require\\s*\\(\\s*shares|if\\s*\\(.*balance.*<\\s*amount.*revert|unchecked'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — subtraction-without-gt-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results

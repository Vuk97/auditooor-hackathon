"""
deposit-allocator-hardcoded-index-with-multi-operator-array — generated from reference/patterns.dsl/deposit-allocator-hardcoded-index-with-multi-operator-array.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py deposit-allocator-hardcoded-index-with-multi-operator-array.yaml
Source: auditooor-R108-kiln-v1-deposit-on-one-operator
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DepositAllocatorHardcodedIndexWithMultiOperatorArray(AbstractDetector):
    ARGUMENT = "deposit-allocator-hardcoded-index-with-multi-operator-array"
    HELP = "Contract maintains a multi-element operator/pool/validator array AND exposes admin `addX` API, but the deposit-routing helper unconditionally targets index 0 (or another fixed literal). New deposits ALL go to that one index, ignoring the array structure. Currently dormant in kiln V1 because `addOper"
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/deposit-allocator-hardcoded-index-with-multi-operator-array.yaml"
    WIKI_TITLE = "Deposit allocator hardcodes operator/pool index 0 despite multi-element array API"
    WIKI_DESCRIPTION = "Many staking / liquid-staking protocols structure their state as an array of operators / pools / providers to support multi-operator load balancing, fee diversity, and operator-specific failure isolation. The allocator function (`_deposit`, `_route`, `_allocate`) is supposed to choose an index dynamically based on availability, weighting, or round-robin policy. A common bug: the allocator is imple"
    WIKI_EXPLOIT_SCENARIO = "Kiln V1: `_depositOnOneOperator(0, count)` — comment-named for the single-operator config, hardcoded literal 0 as operator index. `addOperator` caps at length==1 so the literal 0 is currently the only valid index. V2 ships with `MAX_OPERATORS = 5` to support a multi-operator launch; tests pass because the existing routing always picked operator 0 anyway. Every staked validator on V2 is operated by"
    WIKI_RECOMMENDATION = "Make the allocator-to-array binding architecturally explicit. (1) Replace literal indexes with `operators.value.length`-aware selection: round-robin, weighted by `availableKeys`, or least-funded-first. (2) Add an invariant test: `forall (i,j) in operators: |funded[i] - funded[j]| <= 1` (round-robin)"

    _PRECONDITIONS = [{'contract.source_matches_regex': '\\b(operators|pools|validators|recipients|nodeOperators|providers|integrators)\\s*[\\.\\[]|StakingContract|OperatorRegistry|PoolRegistry|NodeOperatorRegistry'}, {'contract.source_matches_regex': 'function\\s+addOperator|function\\s+addPool|function\\s+addValidator|function\\s+addRecipient|function\\s+addProvider|function\\s+addNodeOperator'}]
    _MATCH = [{'function.kind': 'any'}, {'function.body_contains_regex': '_deposit[A-Za-z]*OfOperator\\s*\\(\\s*0\\s*,|_depositOn[A-Za-z]*Operator\\s*\\(\\s*0\\s*,|operators?\\.value\\s*\\[\\s*0\\s*\\]\\.|pools\\s*\\[\\s*0\\s*\\]\\.|validators\\s*\\[\\s*0\\s*\\]\\.|allocateTo\\s*\\(\\s*0\\s*[,\\)]'}, {'function.name_matches': '^(_deposit|_depositOn[A-Za-z]+Operator|_allocate|_route|_distributeDeposit|_processDeposit|allocate|route|onDeposit|distribute)$'}, {'function.body_not_contains_regex': 'roundRobin|nextOperatorIndex|currentIndex\\s*\\+\\+|randomIndex|\\.length\\s*\\)\\s*%|weightedRandom|leastFunded|mostAvailable|operators\\.value\\.length'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — deposit-allocator-hardcoded-index-with-multi-operator-array: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results

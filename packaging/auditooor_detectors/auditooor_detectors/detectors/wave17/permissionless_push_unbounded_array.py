"""
permissionless-push-unbounded-array — generated from reference/patterns.dsl/permissionless-push-unbounded-array.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py permissionless-push-unbounded-array.yaml
Source: solodit-cluster-DOS-WRITER
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PermissionlessPushUnboundedArray(AbstractDetector):
    ARGUMENT = "permissionless-push-unbounded-array"
    HELP = "External/public function with no access-control modifier allows any caller to push to a state array, growing it unbounded. Downstream iterators become gas-DoS-able."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/permissionless-push-unbounded-array.yaml"
    WIKI_TITLE = "Permissionless push to unbounded state array"
    WIKI_DESCRIPTION = "An external or public function without access control writes to a storage array via `arr.push(x)`. Because any caller can invoke it, the array has no natural upper bound — an attacker can cheaply inflate its length. Any later consumer that iterates the full array (reward distributor, vault snapshot, governance tally, auction resolver) must pay per-element gas. Once the array length exceeds the blo"
    WIKI_EXPLOIT_SCENARIO = "A rewards contract tracks active stakers via `address[] public stakers; function register(address s) external { stakers.push(s); }`. Reward distribution loops `for (uint i; i < stakers.length; ++i) { transfer(stakers[i], reward); }`. An attacker calls `register` in a tight loop from a funded EOA (or spams via a contract), inflating `stakers` until the distribution loop costs more than one block's "
    WIKI_RECOMMENDATION = "Either (a) gate the writer with an appropriate access-control modifier (`onlyOwner`, `onlyRoles`), (b) cap the array length with a `require(arr.length < MAX)` precondition and treat overflow as an explicit out-of-capacity error, or (c) restructure the consumer to paginate / use pull-payment / use a "

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_modifier': {'includes': ['onlyOwner', 'onlyAdmin', 'onlyRoles', 'onlyGovernance', 'onlyMinter', 'onlyKeeper'], 'negate': True}}, {'function.body_contains_regex': {'regex': '\\w+\\s*\\.push\\s*\\('}}, {'function.writes_storage_matching': '.*'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — permissionless-push-unbounded-array: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results

"""
a-missed-requirement — generated from reference/patterns.dsl/a-missed-requirement.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-missed-requirement.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AMissedRequirement(AbstractDetector):
    ARGUMENT = "a-missed-requirement"
    HELP = "Function whose name matches the target regex reads a state var matching the read regex, but does NOT contain an internal/high-level call matching the required-call regex."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-missed-requirement.yaml"
    WIKI_TITLE = "A missed requirement"
    WIKI_DESCRIPTION = "Although there is a check in the `takeClaimingSnapshot` function, it is more crucial to include it in the `updateDistributionEventCollectionIds` function as well. Functions reading certain state variables should call validation/update guards."
    WIKI_EXPLOIT_SCENARIO = "Function whose name matches the target regex reads a state var matching the read regex, but does NOT contain an internal/high-level call matching the required-call regex."
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.name_matches': '.*(takeClaimingSnapshot|updateDistributionEventCollectionIds).*'}, {'function.reads_state_var_matching_regex': '.*(takeClaimingSnapshot|updateDistributionEventCollectionIds).*'}, {'function.calls_function_matching': {'regex': '.*(accrue|update|sync|validate|check|refresh).*', 'negate': True}}, {'function.not_leaf_helper': True}, {'function.not_in_skip_list': True}]

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
                info = [f, f" — a-missed-requirement: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results

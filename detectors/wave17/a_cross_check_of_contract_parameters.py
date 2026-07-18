"""
a-cross-check-of-contract-parameters — generated from reference/patterns.dsl/a-cross-check-of-contract-parameters.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-cross-check-of-contract-parameters.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ACrossCheckOfContractParameters(AbstractDetector):
    ARGUMENT = "a-cross-check-of-contract-parameters"
    HELP = "A cross-check of contract parameters"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-cross-check-of-contract-parameters.yaml"
    WIKI_TITLE = "A cross-check of contract parameters"
    WIKI_DESCRIPTION = "If contracts ActivePool, CollSurplusPool, DefaultPool, StabilityPool and BorrowerOperations are deployed with the misconfigured _collateralAddress parameter, they will be unable to withdraw the deposited collateral."
    WIKI_EXPLOIT_SCENARIO = "A cross-check of contract parameters"
    WIKI_RECOMMENDATION = "It is recommended to enforce equ"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.name_matches_regex': '.*(ActivePool|CollSurplusPool|DefaultPool|StabilityPool|BorrowerOperations).*'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.reads_state_var_matching': '.*(balance|amount|total|supply|reserve).*'}, {'function.does_not_call_matching': '.*(accrue|update|sync|validate|check|refresh).*'}]

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
                info = [f, f" — a-cross-check-of-contract-parameters: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results

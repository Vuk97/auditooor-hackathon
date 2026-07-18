"""
glider-missing-zero-address-validation-in-constructor — generated from reference/patterns.dsl/glider-missing-zero-address-validation-in-constructor.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-missing-zero-address-validation-in-constructor.yaml
Source: hexens-glider/missing-zero-address-validation-in-constructor
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderMissingZeroAddressValidationInConstructor(AbstractDetector):
    ARGUMENT = "glider-missing-zero-address-validation-in-constructor"
    HELP = "Missing Zero Address Validation in Constructor"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-missing-zero-address-validation-in-constructor.yaml"
    WIKI_TITLE = "Missing Zero Address Validation in Constructor"
    WIKI_DESCRIPTION = "Constructors set address parameters to state variables without validation"
    WIKI_EXPLOIT_SCENARIO = "Transpiled from Hexens Glider query missing-zero-address-validation-in-constructor. Tags: constructor, validation, zero-address."
    WIKI_RECOMMENDATION = "Apply the check implied by the original Glider query — see hexens-glider source for context."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'function.is_constructor': True}, {'function.has_param_of_type': 'address'}]
    _MATCH = [{'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-missing-zero-address-validation-in-constructor: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results

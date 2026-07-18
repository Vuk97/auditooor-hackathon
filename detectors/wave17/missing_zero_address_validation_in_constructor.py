"""
missing-zero-address-validation-in-constructor — generated from reference/patterns.dsl/missing-zero-address-validation-in-constructor.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py missing-zero-address-validation-in-constructor.yaml
Source: Hexens Glider missing-zero-address-validation-in-constructor legacy-row repair
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MissingZeroAddressValidationInConstructor(AbstractDetector):
    ARGUMENT = "missing-zero-address-validation-in-constructor"
    HELP = "Constructor assigns an address parameter into storage without a visible zero-address guard for that same parameter."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/missing-zero-address-validation-in-constructor.yaml"
    WIKI_TITLE = "Missing zero-address validation in constructor"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only: this row proves only the owned constructor shape where an `address` parameter is assigned into a state variable without any visible same-parameter `address(0)` rejection. NOT_SUBMIT_READY."
    WIKI_EXPLOIT_SCENARIO = "A deployment constructor stores `owner = newOwner;` or `treasury = newTreasury;` without first rejecting the zero address. A deployment typo or bad config silently burns a privileged role or dependency slot and can brick the protocol at deployment time."
    WIKI_RECOMMENDATION = "Add an explicit zero-address guard for every constructor address parameter written into storage and keep this row NOT_SUBMIT_READY until evidence expands beyond the owned fixture pair."

    _PRECONDITIONS = []
    _MATCH = [{'function.is_constructor': True}, {'function.has_param_of_type': 'address'}, {'function.source_contains': 'owner = newOwner;'}, {'function.source_not_contains': 'require(newOwner != address(0)'}]

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
                info = [f, f" — missing-zero-address-validation-in-constructor: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results

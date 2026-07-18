"""
inconsistent-decimal-handling-across-codebase — generated from reference/patterns.dsl/inconsistent-decimal-handling-across-codebase.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py inconsistent-decimal-handling-across-codebase.yaml
Source: zellic audit Blackhaven Core Contracts
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class InconsistentDecimalHandlingAcrossCodebase(AbstractDetector):
    ARGUMENT = "inconsistent-decimal-handling-across-codebase"
    HELP = "Bond-style RBT math mixes hardcoded 18-decimal scale literals with dynamic IERC20Metadata(...).decimals() conversions."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/inconsistent-decimal-handling-across-codebase.yaml"
    WIKI_TITLE = "Inconsistent decimal handling across codebase"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof for the Blackhaven informational finding: one Bond-shaped path hardcodes RBT as 1e18 while valueOfToken reads RBT and input token decimals dynamically. NOT_SUBMIT_READY."
    WIKI_EXPLOIT_SCENARIO = "Bond-style RBT math mixes hardcoded 18-decimal scale literals with dynamic IERC20Metadata(...).decimals() conversions."
    WIKI_RECOMMENDATION = "Do not promote from this fixture smoke alone. Standardize RBT decimal handling on IERC20Metadata(token).decimals() and validate against project-specific token decimal assumptions before submission."

    _PRECONDITIONS = []
    _MATCH = [{'contract.source_contains_any': ['1e18', '10 ** 18']}, {'function.name': 'valueOfToken'}, {'function.source_contains_all': ['IERC20Metadata(address(RBT)).decimals()', 'IERC20Metadata(_token).decimals()']}]

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
                info = [f, f" — inconsistent-decimal-handling-across-codebase: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results

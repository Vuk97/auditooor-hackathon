"""
fx-euler-irm-kink-type-truncation — generated from reference/patterns.dsl/fx-euler-irm-kink-type-truncation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fx-euler-irm-kink-type-truncation.yaml
Source: github:euler-xyz/euler-vault-kit@50c5c90
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FxEulerIrmKinkTypeTruncation(AbstractDetector):
    ARGUMENT = "fx-euler-irm-kink-type-truncation"
    HELP = "IRM constructor accepts kink_ as uint256 but the kink storage field is uint32. Passing a value >type(uint32).max silently truncates it, producing a completely wrong utilization kink and unbounded interest rates at unexpected utilization points."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fx-euler-irm-kink-type-truncation.yaml"
    WIKI_TITLE = "IRM constructor kink parameter is uint256 but stored as uint32 — silent truncation of utilization kink"
    WIKI_DESCRIPTION = "Interest rate model constructors that accept the kink parameter as uint256 but store it in a uint32 field will silently truncate values above 2^32-1. Because the kink is expressed in a type(uint32).max scale, a misconfigured deployment that passes a full uint256 value (e.g., 1e18) will truncate to an arbitrary kink position, producing incorrect interest rate curves. No overflow revert fires becaus"
    WIKI_EXPLOIT_SCENARIO = "Euler (2024): IRMLinearKink constructor received kink_ as uint256. A deployment script passing 0.8e18 (1e18 scale) truncates to 0xDE0B6B3A (≈3.73e9), which in uint32.max scale represents ~87% utilization, silently misconfiguring the IRM."
    WIKI_RECOMMENDATION = "Declare the constructor parameter as uint32 so any out-of-range value reverts at the ABI decoding stage. Alternatively add an explicit bounds check: require(kink_ <= type(uint32).max)."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '^kink$|constructor'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': '^(constructor|initialize)$'}, {'function.body_contains_regex': 'kink\\s*=\\s*kink_|kink_\\s*;'}, {'function.param_list_contains_regex': 'uint256\\s+kink_'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fx-euler-irm-kink-type-truncation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results

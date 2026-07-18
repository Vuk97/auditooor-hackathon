"""
glider-assert-for-input-validation — generated from reference/patterns.dsl/glider-assert-for-input-validation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-assert-for-input-validation.yaml
Source: glider/assert-user-input
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderAssertForInputValidation(AbstractDetector):
    ARGUMENT = "glider-assert-for-input-validation"
    HELP = "Function uses `assert(x OP y)` to validate caller-supplied input. `assert` is reserved for invariants that should never fail; using it for input validation wastes all remaining gas and signals a protocol invariant violation to monitoring tools."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-assert-for-input-validation.yaml"
    WIKI_TITLE = "`assert` used for external input validation (gas burn + wrong semantics)"
    WIKI_DESCRIPTION = "Post-0.8.0, `assert` still reverts with `Panic(0x01)`. Using it for caller-provided input triggers a panic signal reserved for protocol bugs, misleading monitoring dashboards and burning remaining gas (unlike `require` which returns the gas on failure)."
    WIKI_EXPLOIT_SCENARIO = "Griefer calls the function with inputs that fail the assert. The panic revert burns the caller's gas and spams error-monitoring dashboards with 'protocol invariant broken' alerts — ops wastes time triaging a false positive."
    WIKI_RECOMMENDATION = "Use `require(cond, \"msg\")` or `if (!cond) revert MyError();` for input validation. Reserve `assert` for logical invariants that should be unreachable."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': 'assert\\s*\\(\\s*\\w+\\s*(==|!=|<|>|<=|>=)\\s*\\w+\\s*\\)'}, {'function.has_param_of_type': 'uint256'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-assert-for-input-validation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results

"""
glider-division-before-multiplication — generated from reference/patterns.dsl/glider-division-before-multiplication.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-division-before-multiplication.yaml
Source: glider/division-before-multiplication
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderDivisionBeforeMultiplication(AbstractDetector):
    ARGUMENT = "glider-division-before-multiplication"
    HELP = "Classic Solidity precision bug: `(a / b) * c` truncates the intermediate divisor, losing precision. Rewrite as `(a * c) / b` or use FullMath.mulDiv."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-division-before-multiplication.yaml"
    WIKI_TITLE = "Division before multiplication (precision loss)"
    WIKI_DESCRIPTION = "In integer arithmetic, `(a / b) * c` computes the floored quotient first and then multiplies, which loses precision proportional to `b - (a mod b)`. The equivalent `(a * c) / b` preserves up to the last whole unit of precision. When this composed expression is a fee, share, or reward calculation, the precision loss accrues into real user loss over many interactions."
    WIKI_EXPLOIT_SCENARIO = "Vault computes `pendingReward = (stakedAmount / totalStaked) * rewardsPerBlock`. With `stakedAmount < totalStaked`, the first division truncates to 0, so every individual staker pending is 0 — rewards accumulate in the contract but nobody can ever claim them."
    WIKI_RECOMMENDATION = "Reorder to multiply first: `(a * c) / b`. For very large numerators that could overflow, use OZ `Math.mulDiv` or Solmate `FixedPointMathLib.mulDivDown`."

    _PRECONDITIONS = [{'contract.source_matches_regex': '\\*|/'}]
    _MATCH = [{'function.kind': 'any'}, {'function.body_contains_regex': '\\(\\s*\\w+\\s*/\\s*\\w+\\s*\\)\\s*\\*|\\w+\\s*/\\s*\\w+\\s*\\*\\s*\\w+'}, {'function.body_not_contains_regex': 'FullMath\\.mulDiv|mulDivDown|FixedPointMathLib'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-division-before-multiplication: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results

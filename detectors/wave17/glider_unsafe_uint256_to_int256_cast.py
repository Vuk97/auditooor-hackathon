"""
glider-unsafe-uint256-to-int256-cast — generated from reference/patterns.dsl/glider-unsafe-uint256-to-int256-cast.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-unsafe-uint256-to-int256-cast.yaml
Source: hexens-glider/unsafe-uint256-to-int256-cast
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderUnsafeUint256ToInt256Cast(AbstractDetector):
    ARGUMENT = "glider-unsafe-uint256-to-int256-cast"
    HELP = "Explicit `int256(x)` cast on a uint256 without a `x <= type(int256).max` guard. For values > 2^255-1 the cast silently becomes negative."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-unsafe-uint256-to-int256-cast.yaml"
    WIKI_TITLE = "Unsafe uint256 → int256 cast (signed overflow)"
    WIKI_DESCRIPTION = "`int256(someUint)` is a bit-preserving cast — for any input ≥ 2^255 the resulting signed value is negative. Code that feeds this into a comparison (`if (signedAmt > 0)`) or accumulation flips invariants without any revert. SafeCast.toInt256 is the canonical protection."
    WIKI_EXPLOIT_SCENARIO = "Staking contract tracks deltas: `int256 delta = int256(userAmount) - int256(prevAmount);`. User deposits `2**255` via a burn/mint shortcut. `int256(userAmount)` becomes a large negative. Delta computes as a nonsense value that passes the solvency check but corrupts net-balance invariants."
    WIKI_RECOMMENDATION = "Use `SafeCast.toInt256(x)` which reverts on overflow. If inline, `require(x <= uint256(type(int256).max), \"overflow\"); int256 y = int256(x);`."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'int256\\s*\\('}]
    _MATCH = [{'function.kind': 'any'}, {'function.body_contains_regex': '=\\s*int256\\s*\\(\\s*[a-zA-Z_]\\w*'}, {'function.body_not_contains_regex': 'type\\s*\\(\\s*int256\\s*\\)\\.max|int256\\s*\\(\\s*uint128\\s*\\(|SafeCast|toInt256|require\\s*\\(\\s*\\w+\\s*<=\\s*(uint256\\(type\\(int256\\)\\.max\\)|2\\s*\\*\\*\\s*255\\s*-\\s*1)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-unsafe-uint256-to-int256-cast: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results

"""
unsafe-uint-to-int-cast — generated from reference/patterns.dsl/unsafe-uint-to-int-cast.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py unsafe-uint-to-int-cast.yaml
Source: solodit/unsafe-cast-class
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class UnsafeUintToIntCast(AbstractDetector):
    ARGUMENT = "unsafe-uint-to-int-cast"
    HELP = "External/public function casts a uint value to a signed int (e.g. int256(uintValue)) without SafeCast. If the uint exceeds 2**(N-1) the result is silently negative, which flips signs in tick math, margin calcs, and P&L accumulators."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/unsafe-uint-to-int-cast.yaml"
    WIKI_TITLE = "Unsafe uint-to-int cast: bit-preserving reinterpretation silently flips sign"
    WIKI_DESCRIPTION = "Solidity's `intN(uintM)` conversion is a bit-level reinterpretation, not a range-checked cast. When the uint value has the high bit set (>= 2**(N-1)) the resulting signed integer is a large negative number, and Solidity 0.8+ overflow checks do not fire because no arithmetic occurs. The bug is common in tick math (Uniswap V3/V4 style), funding-rate diffs, margin and P&L accumulators, and concentrat"
    WIKI_EXPLOIT_SCENARIO = "A perp exchange tracks cumulative funding as `uint256 cumulativeFunding`. The settlement path computes trader P&L as `int256 delta = int256(cumulativeFundingNow) - int256(cumulativeFundingAtEntry);`. When `cumulativeFundingNow` exceeds 2**255, the int256 cast becomes a large negative number, the subtraction wraps, and every trader's settlement reports a wildly incorrect P&L. Attackers with open po"
    WIKI_RECOMMENDATION = "Route every uint→int conversion through OpenZeppelin `SafeCast.toInt256` / `toInt128` / `toInt64`, which reverts when the source value exceeds the target's positive range. For home-rolled code use `require(x <= uint256(type(int256).max), 'cast overflow')` immediately before the cast. Never rely on 0"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': 'int\\d*\\s*\\(\\s*uint|int\\d+\\s*\\(\\s*uint\\d+|\\(int\\d+\\)\\s*\\w+\\s*\\+|\\(int\\d+\\)\\s*\\w+\\s*-'}, {'function.body_not_contains_regex': 'SafeCast|toInt\\s*\\(|toInt256|toInt128|toInt64|_safeCast|require\\s*\\(\\s*\\w+\\s*<=\\s*type\\s*\\(\\s*uint\\d+\\s*\\)\\.max\\s*/\\s*2'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — unsafe-uint-to-int-cast: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results

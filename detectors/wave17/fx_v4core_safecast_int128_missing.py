"""
fx-v4core-safecast-int128-missing — generated from reference/patterns.dsl/fx-v4core-safecast-int128-missing.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fx-v4core-safecast-int128-missing.yaml
Source: github:Uniswap/v4-core@d47ecf9
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FxV4coreSafecastInt128Missing(AbstractDetector):
    ARGUMENT = "fx-v4core-safecast-int128-missing"
    HELP = "toUint128() overload for int128 input is missing or lacks a negative-value guard. Direct uint128(int128) casts silently wrap negative values to large positives, corrupting signed balance deltas in pool accounting."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fx-v4core-safecast-int128-missing.yaml"
    WIKI_TITLE = "SafeCast missing int128->uint128 overload — negative delta wraps silently to large uint"
    WIKI_DESCRIPTION = "AMMs using int128 for balance deltas (like Uniswap v4 BalanceDelta) frequently cast signed deltas to unsigned amounts. Without an explicit toUint128(int128) function that checks x >= 0, callers use bare uint128(x) which wraps negative values. A negative delta of -1 becomes 2^128 - 1, causing catastrophic overstatement of owed amounts or pool reserves."
    WIKI_EXPLOIT_SCENARIO = "Uniswap v4 audit (Spearbit/Trail of Bits, 2023-2024): BalanceDelta encodes int128 amounts. Without a safe cast, a negative delta fed into uint128() in pool accounting produces a 2^128 - 1 reserve credit instead of reverting."
    WIKI_RECOMMENDATION = "Add `function toUint128(int128 x) internal pure returns (uint128 y) { if (x < 0) revert SafeCastOverflow(); y = uint128(x); }` to the SafeCast library. Enforce its use through linting rules that flag bare uint128(int128_var) casts."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '^(toUint128|toUint256|toInt128)$'}]
    _MATCH = [{'function.kind': 'internal'}, {'function.name_matches': '^toUint128$'}, {'function.body_contains_regex': 'uint128\\s*\\('}, {'function.body_not_contains_regex': 'x\\s*<\\s*0|int128.*<.*0|SafeCastOverflow|revert'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fx-v4core-safecast-int128-missing: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results

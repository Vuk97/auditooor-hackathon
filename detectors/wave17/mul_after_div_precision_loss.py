"""
mul-after-div-precision-loss — generated from reference/patterns.dsl/mul-after-div-precision-loss.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py mul-after-div-precision-loss.yaml
Source: auto-mined-from-diffs/added-mulDiv-math-cluster
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MulAfterDivPrecisionLoss(AbstractDetector):
    ARGUMENT = "mul-after-div-precision-loss"
    HELP = "External/public function computes `a / b * c` (division before multiplication) without mulDiv. Integer division truncates; the final result is systematically smaller than mathematically correct, corrupting share-conversion, fee, and reward accounting."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/mul-after-div-precision-loss.yaml"
    WIKI_TITLE = "Mul-after-div precision loss: integer division truncates before multiplication"
    WIKI_DESCRIPTION = "The function body contains an arithmetic expression of the form `a / b * c` — division evaluated first, multiplication second. Integer division in Solidity truncates toward zero, so any remainder `a mod b` is lost before the multiplication. The final result is always less than or equal to the mathematically correct `a * c / b`, and the gap grows with the size of the remainder. In ERC-4626 share/as"
    WIKI_EXPLOIT_SCENARIO = "A lending market computes borrower fee as `fee = principal / YEAR_SECONDS * ratePerSecond * elapsed`. A borrower takes a tiny loan of `principal = 1e6` with `ratePerSecond = 1e12` for a 10-second block. The intended fee is `1e6 * 1e12 * 10 / YEAR_SECONDS ≈ 316` wei. Because division happens first and `1e6 / 31_536_000 == 0`, the computed fee is exactly zero and the borrower pays no interest. Repea"
    WIKI_RECOMMENDATION = "Replace every `a / b * c` sequence with `Math.mulDiv(a, c, b)` from `@openzeppelin/contracts/utils/math/Math.sol`, which performs a full-width 512-bit multiplication of `a * c` followed by a single floor-division by `b`. For rounding-up semantics use `Math.mulDiv(a, c, b, Math.Rounding.Up)`. When in"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.not_slither_synthetic': True}, {'function.body_contains_regex': '\\w+\\s*\\/\\s*\\w+\\s*\\*\\s*\\w+|\\(\\s*\\w+\\s*\\/\\s*\\w+\\s*\\)\\s*\\*'}, {'function.body_not_contains_regex': 'mulDiv|FullMath|PRBMath|_mulDiv|fullMulDiv|Math\\.mul'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — mul-after-div-precision-loss: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
